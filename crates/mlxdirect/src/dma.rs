// Источник: pci-driver 0.1.4 (iommu.rs: PciIommu::map/unmap → VFIO_IOMMU_MAP_DMA/
// VFIO_IOMMU_UNMAP_DMA; backends/vfio/containers.rs: vfio_iommu_map_dma, set_iommu
// VFIO_TYPE1v2 — пин всех страниц диапазона при map (eager pin); regions/mod.rs:
// PciRegion — sealed-трейт, расширение через AsPciSubregion (blanket
// `impl PciRegion for T where T: AsPciSubregion + Debug + Send + Sync`),
// PciMemoryRegion::new_raw — volatile-регион поверх сырой памяти, паттерн
// `impl AsPciSubregion for &T` как у OwningPciRegion); Linux VFIO docs
// (Documentation/driver-api/vfio.rst: VFIO_IOMMU_MAP_DMA, vaddr==iova допустим,
// выравнивание iova/size на страницу IOMMU); DMA-контракт — спека
// docs/superpowers/specs/2026-11-08-vendored-mlx5cmd-replacement-design.md §4
// (окно 0x1000_0000..0x2000_0000, identity-map, eager pin, MAP_FIXED;
// потребитель arm.rs: mem.len()/mem.write_u8 (PciRegion), memory.as_ptr().unwrap()).

use std::sync::{Arc, Mutex};

use pci_driver::iommu::PciIommu;
use pci_driver::regions::{AsPciSubregion, PciMemoryRegion, PciRegion, PciSubregion, Permissions};

use crate::err::{Error, Result};

/// База единого DMA-окна (жёсткий контракт, спека §4): `0x1000_0000`.
pub const DMA_WINDOW_BASE: usize = 0x1000_0000;
/// Размер окна: 256 МБ (`0x1000_0000..0x2000_0000`).
pub const DMA_WINDOW_SIZE: usize = 0x1000_0000;
/// Страница аллокатора (MTT-гранула: len = 0x1000 × pages).
pub const DMA_PAGE_SIZE: usize = 0x1000;

/// Свободный непрерывный ран страниц (индексы от базы окна).
#[derive(Debug, Clone, Copy)]
struct FreeRun {
    start: usize,
    pages: usize,
}

/// Аллокатор страниц поверх единого identity-map DMA-окна: vaddr == IOVA,
/// окно маплится целиком один раз (eager pin), страницы субаллокируются
/// first-fit-фрилистом с коалесценцией соседних ранов на возврате.
#[derive(Debug)]
pub struct DmaAlloc {
    base: *mut u8,
    len: usize,
    /// Окно создано этим аллокатором (mmap в `map_window`) → munmap на drop.
    owned: bool,
    pool: Arc<Mutex<Vec<FreeRun>>>,
}

// base — база собственного mmap-окна (для over_window — валидна, пока вызывающий
// держит маппинг); пул — под Mutex.
unsafe impl Send for DmaAlloc {}
unsafe impl Sync for DmaAlloc {}

impl DmaAlloc {
    /// Производственный конструктор: `mmap(MAP_FIXED)` окна на
    /// [`DMA_WINDOW_BASE`] + `VFIO_IOMMU_MAP_DMA` с IOVA == vaddr
    /// (pci-driver `PciIommu::map`; TYPE1v2 пинит все страницы диапазона при
    /// map — eager pin). Iommu-маппинг живёт, пока жив контейнер VFIO
    /// (держится сессией Direct).
    pub fn map_window(iommu: &PciIommu) -> Result<Self> {
        if iommu.alignment() > DMA_PAGE_SIZE {
            return Err(Error::Unsupported(format!(
                "IOMMU iova-alignment {:#x} больше страницы окна {:#x}",
                iommu.alignment(),
                DMA_PAGE_SIZE
            )));
        }
        let end = (DMA_WINDOW_BASE + DMA_WINDOW_SIZE) as u64;
        let covered = iommu
            .valid_iova_ranges()
            .iter()
            .any(|r| r.start <= DMA_WINDOW_BASE as u64 && end <= r.end);
        if !covered {
            return Err(Error::Unsupported(format!(
                "окно {DMA_WINDOW_BASE:#x}..{end:#x} вне допустимых iova-диапазонов IOMMU"
            )));
        }
        let ptr = unsafe {
            libc::mmap(
                DMA_WINDOW_BASE as *mut libc::c_void,
                DMA_WINDOW_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(Error::Io(format!(
                "mmap MAP_FIXED @{DMA_WINDOW_BASE:#x} +{DMA_WINDOW_SIZE:#x}: {}",
                std::io::Error::last_os_error()
            )));
        }
        let mapped = unsafe {
            iommu.map(
                DMA_WINDOW_BASE as u64,
                DMA_WINDOW_SIZE,
                ptr.cast::<u8>(),
                Permissions::ReadWrite,
            )
        };
        match mapped {
            Ok(()) => Ok(DmaAlloc {
                base: ptr.cast(),
                len: DMA_WINDOW_SIZE,
                owned: true,
                pool: Arc::new(Mutex::new(vec![FreeRun {
                    start: 0,
                    pages: DMA_WINDOW_SIZE / DMA_PAGE_SIZE,
                }])),
            }),
            Err(e) => {
                unsafe { libc::munmap(ptr, DMA_WINDOW_SIZE) };
                Err(Error::Io(format!(
                    "VFIO_IOMMU_MAP_DMA {DMA_WINDOW_BASE:#x} +{DMA_WINDOW_SIZE:#x}: {e}"
                )))
            }
        }
    }

    /// Конструктор поверх уже смапленного окна (тесты: анонимный mmap с
    /// фиктивной базой; кастомные окна). Маппинг принадлежит вызывающему.
    pub fn over_window(base: *mut u8, len: usize) -> Self {
        debug_assert_eq!(len % DMA_PAGE_SIZE, 0, "окно кратно странице");
        DmaAlloc {
            base,
            len,
            owned: false,
            pool: Arc::new(Mutex::new(vec![FreeRun {
                start: 0,
                pages: len / DMA_PAGE_SIZE,
            }])),
        }
    }

    /// База окна (vaddr == IOVA): `Direct::dma_region_base` читает её отсюда.
    pub fn window_base(&self) -> *mut u8 {
        self.base
    }

    /// Дескриптор того же окна с общим пулом (owned=false — drop такого
    /// дескриптора НЕ munmap'ает окно). Для process-lifetime заимствований
    /// (CMDQ сессии, Task 10): оригинал остаётся у Direct, дескриптор
    /// утекает в Box::leak для Cmdq<'static>.
    pub(crate) fn share(&self) -> DmaAlloc {
        DmaAlloc {
            base: self.base,
            len: self.len,
            owned: false,
            pool: Arc::clone(&self.pool),
        }
    }

    /// Выделить `pages` смежных страниц окна; исчерпание/0/сверх окна → None
    /// (без паники). Память не обнуляется.
    pub fn alloc(&self, pages: usize) -> Option<AllocationGuard> {
        if pages == 0 || pages > self.len / DMA_PAGE_SIZE {
            return None;
        }
        let mut runs = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        let idx = runs.iter().position(|r| r.pages >= pages)?;
        let run = runs[idx];
        if run.pages == pages {
            runs.remove(idx);
        } else {
            runs[idx] = FreeRun {
                start: run.start + pages,
                pages: run.pages - pages,
            };
        }
        let ptr = unsafe { self.base.add(run.start * DMA_PAGE_SIZE) };
        let region =
            unsafe { PciMemoryRegion::new_raw(ptr, pages * DMA_PAGE_SIZE, Permissions::ReadWrite) };
        Some(AllocationGuard {
            pool: Arc::clone(&self.pool),
            region,
            start_page: run.start,
            pages,
        })
    }
}

impl Drop for DmaAlloc {
    fn drop(&mut self) {
        if self.owned {
            unsafe { libc::munmap(self.base.cast(), self.len) };
        }
    }
}

/// Выделенный кусок DMA-окна (pages страниц): volatile-доступ через трейт
/// `PciRegion` (sealed в pci-driver — расширяется через `AsPciSubregion`,
/// как OwningPciRegion), inherent `as_ptr` — IOVA == vaddr для MTT.
/// Drop возвращает страницы в пул. Guard не должен переживать DmaAlloc.
#[derive(Debug)]
pub struct AllocationGuard {
    pool: Arc<Mutex<Vec<FreeRun>>>,
    region: PciMemoryRegion<'static>,
    start_page: usize,
    pages: usize,
}

impl AllocationGuard {
    /// Указатель на начало выделенных страниц; он же — IOVA (identity-окно).
    pub fn as_ptr(&self) -> Option<*mut u8> {
        PciRegion::as_mut_ptr(&self.region)
    }
}

impl Drop for AllocationGuard {
    fn drop(&mut self) {
        return_pages(&self.pool, self.start_page, self.pages);
    }
}

/// `&AllocationGuard` как подрегион окна → `PciRegion` через blanket-impl
/// pci-driver (паттерн OwningPciRegion: impl AsPciSubregion для ссылки).
impl<'a> AsPciSubregion<'a> for &'a AllocationGuard {
    fn as_subregion(&self) -> PciSubregion<'a> {
        let region: &'a PciMemoryRegion<'a> = &self.region;
        region.as_subregion()
    }
}

/// Прямые вызовы `guard.len()/write_u8/…` (владелец по значению, как
/// arm.rs) резолвятся через Deref на сам `PciMemoryRegion` (у него прямой
/// impl PciRegion); вариант только через blanket AsPciSubregion не
/// проходит метод-резолюцию на value-ресивере из-за привязки времён жизни.
impl std::ops::Deref for AllocationGuard {
    type Target = PciMemoryRegion<'static>;

    fn deref(&self) -> &Self::Target {
        &self.region
    }
}

/// Возврат рана в пул: вставка по сортировке + коалесценция соседей.
fn return_pages(pool: &Mutex<Vec<FreeRun>>, start: usize, pages: usize) {
    let mut runs = pool.lock().unwrap_or_else(|e| e.into_inner());
    let pos = match runs.binary_search_by_key(&start, |r| r.start) {
        Ok(_) => return,
        Err(pos) => pos,
    };
    runs.insert(pos, FreeRun { start, pages });
    if runs
        .get(pos + 1)
        .is_some_and(|next| next.start == start + pages)
    {
        runs[pos].pages += runs[pos + 1].pages;
        runs.remove(pos + 1);
    }
    if pos > 0 && runs[pos - 1].start + runs[pos - 1].pages == start {
        runs[pos - 1].pages += runs[pos].pages;
        runs.remove(pos);
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use pci_driver::regions::PciRegion;

    use super::*;

    /// Мок окна: анонимный mmap (ядро выбирает фиктивную базу), munmap на drop.
    struct MockWindow {
        ptr: *mut u8,
        len: usize,
    }

    impl MockWindow {
        fn new(pages: usize) -> Self {
            let len = pages * DMA_PAGE_SIZE;
            let p = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(
                p,
                libc::MAP_FAILED,
                "mock mmap: {}",
                std::io::Error::last_os_error()
            );
            MockWindow { ptr: p.cast(), len }
        }
    }

    impl Drop for MockWindow {
        fn drop(&mut self) {
            unsafe { libc::munmap(self.ptr.cast(), self.len) };
        }
    }

    fn mock(pages: usize) -> (MockWindow, DmaAlloc) {
        let w = MockWindow::new(pages);
        let a = DmaAlloc::over_window(w.ptr, w.len);
        (w, a)
    }

    fn in_window(w: &MockWindow, p: *mut u8, pages: usize) -> bool {
        let (s, e) = (w.ptr as usize, w.ptr as usize + w.len);
        let (ps, pe) = (p as usize, p as usize + pages * DMA_PAGE_SIZE);
        ps >= s && pe <= e
    }

    /// (а) alloc в пределах окна: выравнивание, as_ptr внутри окна,
    /// трейт-поверхность PciRegion (len/write_u8/read_u8/write_le_u32,
    /// выход за пределы → Err, не паника).
    #[test]
    fn alloc_in_mock_window_is_page_aligned_and_trait_rw_works() {
        let (w, a) = mock(64);
        assert_eq!(a.window_base(), w.ptr, "база аллокатора — база мок-окна");
        let g = a.alloc(4).expect("4 страницы из 64");
        let p = g.as_ptr().expect("as_ptr");
        assert_eq!(p as usize % DMA_PAGE_SIZE, 0, "страничное выравнивание");
        assert!(in_window(&w, p, 4), "as_ptr в пределах мок-окна");
        assert_eq!(g.len(), (4 * DMA_PAGE_SIZE) as u64);
        let _as_trait_obj: &dyn PciRegion = &*g;
        g.write_u8(0x123, 0xab).expect("write_u8");
        assert_eq!(g.read_u8(0x123).expect("read_u8"), 0xab);
        g.write_le_u32(0x1000, 0xdead_beef).expect("write_le_u32");
        assert_eq!(g.read_le_u32(0x1000).expect("read_le_u32"), 0xdead_beef);
        assert!(
            g.write_u8(4 * DMA_PAGE_SIZE as u64, 0).is_err(),
            "офсет за пределами — Err"
        );
    }

    /// (б) исчерпание → None: точное заполнение, сверх окна, 0 страниц,
    /// фрагментация (нет непрерывного рана).
    #[test]
    fn exhaustion_returns_none() {
        let (_w, a) = mock(8);
        let g = a.alloc(8).expect("всё окно");
        assert!(a.alloc(1).is_none(), "окно исчерпано");
        assert!(a.alloc(9).is_none(), "больше окна");
        assert!(a.alloc(0).is_none(), "0 страниц — дегенерат");
        drop(g);

        let g1 = a.alloc(4).unwrap();
        let g2 = a.alloc(2).unwrap();
        drop(g1);
        assert!(
            a.alloc(5).is_none(),
            "фрагментация: дырка 4 + хвост 2, рана 5 нет"
        );
        drop(g2);
        assert!(a.alloc(8).is_some(), "после возврата всё окно снова целое");
    }

    /// (в) drop guard → страницы возвращены, повторный alloc того же размера
    /// успешен (тот же блок).
    #[test]
    fn drop_returns_pages_and_realloc_reuses_block() {
        let (_w, a) = mock(16);
        let g1 = a.alloc(4).unwrap();
        let p1 = g1.as_ptr().unwrap();
        drop(g1);
        let g2 = a.alloc(4).unwrap();
        assert_eq!(g2.as_ptr().unwrap(), p1, "тот же блок после drop → realloc");
    }

    /// (г) два живых guard не пересекаются; запись одного не видна в другом.
    #[test]
    fn two_live_guards_are_disjoint() {
        let (w, a) = mock(16);
        let g1 = a.alloc(4).unwrap();
        let g2 = a.alloc(4).unwrap();
        let (p1, p2) = (g1.as_ptr().unwrap() as usize, g2.as_ptr().unwrap() as usize);
        assert!(
            p1 + 4 * DMA_PAGE_SIZE <= p2 || p2 + 4 * DMA_PAGE_SIZE <= p1,
            "диапазоны guard не пересекаются"
        );
        assert!(in_window(&w, g1.as_ptr().unwrap(), 4));
        assert!(in_window(&w, g2.as_ptr().unwrap(), 4));
        g1.write_u8(0, 0xaa).unwrap();
        assert_ne!(
            g2.read_u8(0).unwrap(),
            0xaa,
            "запись g1 не видна в g2 (анонимные страницы нулевые)"
        );
    }

    /// Жёсткий контракт окна (спека §4): адрес/размер/страница закреплены.
    #[test]
    fn window_constants_pin_hard_contract() {
        assert_eq!(DMA_WINDOW_BASE, 0x1000_0000);
        assert_eq!(DMA_WINDOW_SIZE, 0x2000_0000 - 0x1000_0000);
        assert_eq!(DMA_PAGE_SIZE, 0x1000);
        assert_eq!(DMA_WINDOW_BASE % DMA_PAGE_SIZE, 0);
    }
}
