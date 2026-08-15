//! Remote display topology: what monitors exist and how they are arranged.
//!
//! # Geometry, not assumptions
//!
//! Every question here — which display is to the right, where the pointer lands after
//! crossing an edge, which display a point falls in — is answered from the actual
//! rectangles the host's OS reported. Nothing assumes displays are the same size, the
//! same DPI, arranged in a row, or aligned along their tops. A monitor above and
//! slightly left of the primary is an ordinary case, not a special one.
//!
//! # Crossing preserves the physical point, not the fraction
//!
//! When the pointer leaves one display and enters another, the naive thing is to carry
//! the normalised position across: 60% down the first display becomes 60% down the
//! second. That is wrong whenever the two differ in height or are not aligned — the
//! pointer visibly jumps.
//!
//! So a crossing converts to the shared virtual-desktop coordinate space, finds the
//! neighbour there, and re-normalises inside it. A pointer leaving at a given physical
//! height arrives at that same physical height, which is what the operator sees on the
//! two monitors in front of them.
//!
//! # Coordinate space
//!
//! [`DisplayInfo::origin_x`], `origin_y`, `width` and `height` place each display in
//! one shared virtual desktop, in the units the host's enumerator reported. All
//! arithmetic here stays in that single space, so mixed resolutions and mixed scale
//! factors compose correctly without any per-display conversion.

use rc_protocol::desktop::DisplayInfo;

/// Which way the pointer left a display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Edge {
    /// Off the left-hand side.
    Left,
    /// Off the right-hand side.
    Right,
    /// Off the top.
    Top,
    /// Off the bottom.
    Bottom,
}

impl Edge {
    /// Every edge, for exhaustive tests and for scanning all four directions.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [Self::Left, Self::Right, Self::Top, Self::Bottom]
    }

    /// The edge a pointer would enter through, coming from this one.
    #[must_use]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
            Self::Top => Self::Bottom,
            Self::Bottom => Self::Top,
        }
    }
}

/// How far inside the neighbour a crossing lands, in virtual-desktop pixels.
///
/// Aiming at the neighbour's outermost pixel is fragile in two separate ways. Windows
/// normalises absolute positions through a 16-bit range spanning the whole virtual
/// desktop, so the boundary column can round back across the edge onto the display the
/// pointer just left — observed in practice on a two-monitor machine. And even where
/// the arithmetic is exact, a pointer sitting exactly on the boundary is one sample
/// away from being pushed back, which reads as the cursor sticking to the seam.
///
/// Landing a couple of pixels inside is immune to both and is invisible to the
/// operator: it is the same behaviour a physical multi-monitor desktop has.
const ENTRY_INSET: i64 = 2;

/// Where the pointer ends up after crossing into another display.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Crossing {
    /// The display entered.
    pub display: u8,
    /// Horizontal position within it, 0.0–1.0.
    pub x: f32,
    /// Vertical position within it, 0.0–1.0.
    pub y: f32,
}

/// The remote machine's monitors and their arrangement.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DisplayTopology {
    displays: Vec<DisplayInfo>,
}

impl DisplayTopology {
    /// A topology over `displays`.
    #[must_use]
    pub fn new(displays: Vec<DisplayInfo>) -> Self {
        Self { displays }
    }

    /// Every display, in the order the host reported them.
    #[must_use]
    pub fn all(&self) -> &[DisplayInfo] {
        &self.displays
    }

    /// How many displays there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.displays.len()
    }

    /// Whether no display is known.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.displays.is_empty()
    }

    /// The display with `index`.
    #[must_use]
    pub fn get(&self, index: u8) -> Option<&DisplayInfo> {
        self.displays.iter().find(|display| display.index == index)
    }

    /// The primary display, or the first known one if none is flagged.
    ///
    /// Falling back rather than returning `None` matters: a host that flags no primary
    /// still has monitors, and a session with nowhere to go would be worse than a
    /// session on an arbitrary but real display.
    #[must_use]
    pub fn primary(&self) -> Option<&DisplayInfo> {
        self.displays
            .iter()
            .find(|display| display.primary)
            .or_else(|| self.displays.first())
    }

    /// Whether `index` still exists.
    #[must_use]
    pub fn contains(&self, index: u8) -> bool {
        self.get(index).is_some()
    }

    /// The display a session on `index` should fall back to when `index` disappears.
    ///
    /// Returns `index` unchanged while it still exists, so this is safe to call on
    /// every topology update.
    #[must_use]
    pub fn resolve(&self, index: u8) -> Option<u8> {
        if self.contains(index) {
            return Some(index);
        }
        self.primary().map(|display| display.index)
    }

    /// The bounds of `index` in the virtual desktop, as `(left, top, right, bottom)`.
    ///
    /// Right and bottom are exclusive, matching how the rectangles are reported.
    #[must_use]
    fn bounds(display: &DisplayInfo) -> (i64, i64, i64, i64) {
        let left = i64::from(display.origin_x);
        let top = i64::from(display.origin_y);
        (
            left,
            top,
            left + i64::from(display.width),
            top + i64::from(display.height),
        )
    }

    /// Convert a position within `index` to a virtual-desktop point.
    #[must_use]
    pub fn to_global(&self, index: u8, x: f32, y: f32) -> Option<(i64, i64)> {
        let display = self.get(index)?;
        let (left, top, _, _) = Self::bounds(display);
        Some((
            left + scale(x, display.width),
            top + scale(y, display.height),
        ))
    }

    /// Convert a virtual-desktop point to a position within `index`.
    ///
    /// The result is clamped, so a point outside the display maps to its nearest edge
    /// rather than to a fraction outside 0..=1.
    #[must_use]
    pub fn to_local(&self, index: u8, gx: i64, gy: i64) -> Option<(f32, f32)> {
        let display = self.get(index)?;
        let (left, top, _, _) = Self::bounds(display);
        Some((
            fraction(gx - left, display.width),
            fraction(gy - top, display.height),
        ))
    }

    /// Which display contains a virtual-desktop point.
    #[must_use]
    pub fn at_point(&self, gx: i64, gy: i64) -> Option<u8> {
        self.displays
            .iter()
            .find(|display| {
                let (left, top, right, bottom) = Self::bounds(display);
                gx >= left && gx < right && gy >= top && gy < bottom
            })
            .map(|display| display.index)
    }

    /// The display adjacent to `index` across `edge`, if one is there.
    ///
    /// A neighbour must overlap `index` on the perpendicular axis — two monitors
    /// diagonal to each other are not adjacent, and stepping between them would send
    /// the pointer somewhere the operator was not aiming. Among genuine neighbours the
    /// nearest is chosen, which is what makes three-in-a-row behave.
    #[must_use]
    pub fn adjacent(&self, index: u8, edge: Edge) -> Option<u8> {
        self.adjacent_at(index, edge, None)
    }

    /// The display adjacent across `edge`, preferring the one the pointer is aimed at.
    ///
    /// `at` is the departure point along the edge, in shared coordinates. It matters
    /// whenever one display spans several others — a monitor centred above two will
    /// have two equally-near neighbours below it, and which one is correct depends
    /// entirely on where the pointer left. Ignoring the position would send half of
    /// those crossings to the wrong screen.
    ///
    /// With `None` the nearest is chosen, breaking ties by index so that arrow-key and
    /// menu navigation stay predictable.
    #[must_use]
    pub fn adjacent_at(&self, index: u8, edge: Edge, at: Option<i64>) -> Option<u8> {
        let from = self.get(index)?;
        let (left, top, right, bottom) = Self::bounds(from);

        self.displays
            .iter()
            .filter(|candidate| candidate.index != index)
            .filter_map(|candidate| {
                let (cleft, ctop, cright, cbottom) = Self::bounds(candidate);

                // Distance from the shared edge, and the overlap that makes them
                // neighbours at all.
                let (gap, overlap) = match edge {
                    Edge::Left => (left - cright, span_overlap(top, bottom, ctop, cbottom)),
                    Edge::Right => (cleft - right, span_overlap(top, bottom, ctop, cbottom)),
                    Edge::Top => (top - cbottom, span_overlap(left, right, cleft, cright)),
                    Edge::Bottom => (ctop - bottom, span_overlap(left, right, cleft, cright)),
                };

                // How far the departure point is from this candidate's span. Zero
                // when the pointer is aimed straight at it, which is what makes a
                // display spanning several others pick the right one.
                let miss = at.map_or(0, |point| {
                    let (start, end) = match edge {
                        Edge::Left | Edge::Right => (ctop, cbottom),
                        Edge::Top | Edge::Bottom => (cleft, cright),
                    };
                    if point < start {
                        start - point
                    } else if point >= end {
                        point - end + 1
                    } else {
                        0
                    }
                });

                // `gap >= 0` keeps the candidate on the correct side. Zero is the
                // ordinary case of two monitors placed flush against each other.
                (gap >= 0 && overlap > 0).then_some((miss, gap, candidate.index))
            })
            .min_by_key(|(miss, gap, index)| (*miss, *gap, *index))
            .map(|(_, _, index)| index)
    }

    /// Step off `edge` of `index` at `along`, and land on the neighbour.
    ///
    /// `along` is the position on the departing edge: for a vertical edge it is the
    /// fraction down the display, for a horizontal edge the fraction across it.
    ///
    /// The physical point is preserved rather than the fraction, so a pointer leaving
    /// a 1080p display two-thirds of the way down arrives at that same height on a
    /// 1440p neighbour, whatever its offset.
    #[must_use]
    pub fn cross(&self, index: u8, edge: Edge, along: f32) -> Option<Crossing> {
        let from = self.get(index)?;
        let (left, top, right, bottom) = Self::bounds(from);

        // The point on the departing edge, in shared coordinates.
        let (gx, gy) = match edge {
            Edge::Left => (left, top + scale(along, from.height)),
            Edge::Right => (right - 1, top + scale(along, from.height)),
            Edge::Top => (left + scale(along, from.width), top),
            Edge::Bottom => (left + scale(along, from.width), bottom - 1),
        };

        // Which neighbour depends on where the pointer left, not only on which is
        // nearest: see `adjacent_at`.
        let departure = match edge {
            Edge::Left | Edge::Right => gy,
            Edge::Top | Edge::Bottom => gx,
        };
        let neighbour = self.adjacent_at(index, edge, Some(departure))?;
        let into = self.get(neighbour)?;
        let (nleft, ntop, nright, nbottom) = Self::bounds(into);

        // Entering through the opposite edge of the neighbour, at the same physical
        // offset along it — clamped into the neighbour when the two do not fully
        // overlap, which is what keeps the pointer on screen.
        // Inset so the landing point cannot round back over the boundary; clamped to
        // the neighbour's midpoint so the inset can never overshoot a narrow display.
        let inset_x = ENTRY_INSET.min((nright - nleft) / 2);
        let inset_y = ENTRY_INSET.min((nbottom - ntop) / 2);

        let (ex, ey) = match edge {
            Edge::Left => (nright - 1 - inset_x, gy.clamp(ntop, nbottom - 1)),
            Edge::Right => (nleft + inset_x, gy.clamp(ntop, nbottom - 1)),
            Edge::Top => (gx.clamp(nleft, nright - 1), nbottom - 1 - inset_y),
            Edge::Bottom => (gx.clamp(nleft, nright - 1), ntop + inset_y),
        };

        let (x, y) = self.to_local(neighbour, ex, ey)?;
        Some(Crossing {
            display: neighbour,
            x,
            y,
        })
    }

    /// Which edge a normalised position is touching, within `tolerance`.
    ///
    /// Returns `None` away from the edges, which is the overwhelmingly common case and
    /// costs nothing to answer.
    #[must_use]
    pub fn edge_at(x: f32, y: f32, tolerance: f32) -> Option<Edge> {
        // Horizontal is tested first: a pointer in a corner is far more likely to be
        // moving sideways between monitors than vertically, and picking one keeps the
        // behaviour predictable rather than depending on sub-pixel noise.
        if x <= tolerance {
            Some(Edge::Left)
        } else if x >= 1.0 - tolerance {
            Some(Edge::Right)
        } else if y <= tolerance {
            Some(Edge::Top)
        } else if y >= 1.0 - tolerance {
            Some(Edge::Bottom)
        } else {
            None
        }
    }

    /// The whole virtual desktop's bounds, as `(left, top, right, bottom)`.
    ///
    /// `None` when no display is known.
    #[must_use]
    pub fn virtual_bounds(&self) -> Option<(i64, i64, i64, i64)> {
        let mut bounds: Option<(i64, i64, i64, i64)> = None;
        for display in &self.displays {
            let (left, top, right, bottom) = Self::bounds(display);
            bounds = Some(match bounds {
                None => (left, top, right, bottom),
                Some((l, t, r, b)) => (l.min(left), t.min(top), r.max(right), b.max(bottom)),
            });
        }
        bounds
    }
}

/// A normalised fraction as an offset into `extent`.
///
/// The last addressable pixel is `extent - 1`, so scaling by `extent` and clamping
/// keeps a fraction of 1.0 on the display rather than one pixel past its edge.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the product of a 0..=1 fraction with a u32 extent is bounded by u32, \
              which i64 holds exactly"
)]
fn scale(fraction: f32, extent: u32) -> i64 {
    let clamped = f64::from(fraction.clamp(0.0, 1.0));
    let extent = i64::from(extent);
    let scaled = (clamped * f64::from(u32::try_from(extent).unwrap_or(u32::MAX))).round() as i64;
    scaled.min((extent - 1).max(0))
}

/// An offset into `extent` as a normalised fraction, clamped to the display.
///
/// `f32` is the wire's precision and is ample here: it resolves better than one part
/// in sixteen million, against displays a few thousand pixels wide.
#[expect(
    clippy::cast_possible_truncation,
    reason = "narrowing a clamped 0..=1 f64 to the wire's f32 precision is exact enough \
              to address every pixel of any real display"
)]
fn fraction(offset: i64, extent: u32) -> f32 {
    if extent <= 1 {
        return 0.0;
    }
    let span = f64::from(extent) - 1.0;
    // `offset` is a difference between two virtual-desktop coordinates, both of which
    // originate as i32, so it is far inside f64's exact-integer range.
    let offset = f64::from(i32::try_from(offset).unwrap_or(i32::MAX));
    (offset / span).clamp(0.0, 1.0) as f32
}

/// How much two spans overlap, or zero if they do not.
const fn span_overlap(a_start: i64, a_end: i64, b_start: i64, b_end: i64) -> i64 {
    let start = if a_start > b_start { a_start } else { b_start };
    let end = if a_end < b_end { a_end } else { b_end };
    if end > start { end - start } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display(index: u8, x: i32, y: i32, width: u32, height: u32, primary: bool) -> DisplayInfo {
        DisplayInfo {
            index,
            name: format!("Display {}", index + 1),
            width,
            height,
            scale_factor: 1.0,
            origin_x: x,
            origin_y: y,
            primary,
            refresh_hz: Some(60),
        }
    }

    /// Two 1080p monitors side by side, the left one primary.
    fn side_by_side() -> DisplayTopology {
        DisplayTopology::new(vec![
            display(0, 0, 0, 1920, 1080, true),
            display(1, 1920, 0, 1920, 1080, false),
        ])
    }

    /// The arrangement from the brief: two across, one centred above.
    fn tee() -> DisplayTopology {
        DisplayTopology::new(vec![
            display(0, 0, 0, 1920, 1080, true),
            display(1, 1920, 0, 1920, 1080, false),
            display(2, 960, -1080, 1920, 1080, false),
        ])
    }

    /// Mixed resolutions and a vertical offset, which is where naive maths breaks.
    fn mixed() -> DisplayTopology {
        DisplayTopology::new(vec![
            // 1080p primary.
            display(0, 0, 0, 1920, 1080, true),
            // 1440p to the right, hanging 200px lower.
            display(1, 1920, 200, 2560, 1440, false),
        ])
    }

    #[test]
    fn an_empty_topology_answers_without_panicking() {
        let empty = DisplayTopology::default();
        assert!(empty.is_empty());
        assert_eq!(empty.primary(), None);
        assert_eq!(empty.at_point(0, 0), None);
        assert_eq!(empty.resolve(0), None);
        assert_eq!(empty.virtual_bounds(), None);
    }

    #[test]
    fn the_primary_display_is_found() {
        assert_eq!(side_by_side().primary().unwrap().index, 0);
    }

    #[test]
    fn a_topology_with_no_primary_flag_still_has_one() {
        let topology = DisplayTopology::new(vec![
            display(0, 0, 0, 1920, 1080, false),
            display(1, 1920, 0, 1920, 1080, false),
        ]);
        assert_eq!(topology.primary().unwrap().index, 0);
    }

    #[test]
    fn adjacency_is_found_in_all_four_directions() {
        let topology = tee();
        assert_eq!(topology.adjacent(0, Edge::Right), Some(1));
        assert_eq!(topology.adjacent(1, Edge::Left), Some(0));
        assert_eq!(topology.adjacent(0, Edge::Top), Some(2));
        assert_eq!(topology.adjacent(2, Edge::Bottom), Some(0));
    }

    #[test]
    fn there_is_no_neighbour_off_the_outside_edges() {
        let topology = side_by_side();
        assert_eq!(topology.adjacent(0, Edge::Left), None);
        assert_eq!(topology.adjacent(1, Edge::Right), None);
        assert_eq!(topology.adjacent(0, Edge::Top), None);
        assert_eq!(topology.adjacent(0, Edge::Bottom), None);
    }

    #[test]
    fn diagonal_displays_are_not_adjacent() {
        // Purely diagonal: no shared edge. Stepping between them would move the
        // pointer somewhere the operator was not aiming.
        let topology = DisplayTopology::new(vec![
            display(0, 0, 0, 1920, 1080, true),
            display(1, 1920, 1080, 1920, 1080, false),
        ]);
        assert_eq!(topology.adjacent(0, Edge::Right), None);
        assert_eq!(topology.adjacent(0, Edge::Bottom), None);
    }

    #[test]
    fn the_nearest_neighbour_wins_in_a_row_of_three() {
        let topology = DisplayTopology::new(vec![
            display(0, 0, 0, 1920, 1080, true),
            display(1, 1920, 0, 1920, 1080, false),
            display(2, 3840, 0, 1920, 1080, false),
        ]);
        assert_eq!(topology.adjacent(0, Edge::Right), Some(1));
        assert_eq!(topology.adjacent(2, Edge::Left), Some(1));
    }

    #[test]
    fn displays_left_of_the_origin_work() {
        // A monitor placed to the left of the primary has a negative origin.
        let topology = DisplayTopology::new(vec![
            display(0, 0, 0, 1920, 1080, true),
            display(1, -1920, 0, 1920, 1080, false),
        ]);
        assert_eq!(topology.adjacent(0, Edge::Left), Some(1));
        assert_eq!(topology.adjacent(1, Edge::Right), Some(0));
    }

    #[test]
    fn a_point_is_located_on_the_right_display() {
        let topology = side_by_side();
        assert_eq!(topology.at_point(100, 100), Some(0));
        assert_eq!(topology.at_point(2000, 100), Some(1));
        // Off the desktop entirely.
        assert_eq!(topology.at_point(9000, 100), None);
    }

    #[test]
    fn the_boundary_pixel_belongs_to_exactly_one_display() {
        let topology = side_by_side();
        assert_eq!(topology.at_point(1919, 0), Some(0));
        assert_eq!(topology.at_point(1920, 0), Some(1));
    }

    #[test]
    fn normalised_positions_map_to_the_display_and_back() {
        let topology = side_by_side();
        let (gx, gy) = topology.to_global(1, 0.0, 0.0).unwrap();
        assert_eq!((gx, gy), (1920, 0));
        assert_eq!(topology.at_point(gx, gy), Some(1));

        let (x, y) = topology.to_local(1, gx, gy).unwrap();
        assert!(x.abs() < 0.001 && y.abs() < 0.001);
    }

    #[test]
    fn the_far_corner_stays_on_its_display() {
        // 1.0 must be the last pixel of the display, not the first of the next one.
        let topology = side_by_side();
        let (gx, gy) = topology.to_global(0, 1.0, 1.0).unwrap();
        assert_eq!(topology.at_point(gx, gy), Some(0));
        assert_eq!((gx, gy), (1919, 1079));
    }

    #[test]
    fn crossing_right_lands_on_the_neighbour_at_the_same_height() {
        let topology = side_by_side();
        let crossing = topology.cross(0, Edge::Right, 0.6).unwrap();
        assert_eq!(crossing.display, 1);
        // Entered at the left edge.
        assert!(crossing.x.abs() < 0.01, "entered at x={}", crossing.x);
        // Same height, because the displays are the same size and aligned.
        assert!(
            (crossing.y - 0.6).abs() < 0.01,
            "height not preserved: {}",
            crossing.y
        );
    }

    #[test]
    fn crossing_preserves_the_physical_height_across_different_resolutions() {
        // The case the brief calls out. Display 0 is 1080 tall at y=0; display 1 is
        // 1440 tall starting at y=200. Leaving 0 at 60% down is global y = 648.
        // On display 1 that is (648 - 200) / 1439 ≈ 0.311 — NOT 0.6.
        let topology = mixed();
        let crossing = topology.cross(0, Edge::Right, 0.6).unwrap();
        assert_eq!(crossing.display, 1);

        let (_, gy) = topology.to_global(0, 1.0, 0.6).unwrap();
        let expected = f64::from(i32::try_from(gy - 200).unwrap()) / 1439.0;
        assert!(
            (f64::from(crossing.y) - expected).abs() < 0.01,
            "physical height not preserved: got {} want {expected}",
            crossing.y
        );
        // And emphatically not the naive answer.
        assert!(
            (crossing.y - 0.6).abs() > 0.05,
            "fraction was carried across instead of the physical point"
        );
    }

    #[test]
    fn crossing_clamps_onto_a_neighbour_that_does_not_fully_overlap() {
        // Leaving the very top of display 0 heads for a point above display 1, which
        // starts 200px lower. The pointer must land on display 1's top edge, not off it.
        let topology = mixed();
        let crossing = topology.cross(0, Edge::Right, 0.0).unwrap();
        assert_eq!(crossing.display, 1);
        assert!(crossing.y >= 0.0 && crossing.y <= 1.0);
        assert!(crossing.y.abs() < 0.01, "should hug the top edge");
    }

    #[test]
    fn a_crossing_lands_clear_of_the_boundary() {
        // The regression this inset exists for: a landing point exactly on the seam
        // rounds back onto the display the pointer just left, on real Windows.
        let topology = side_by_side();
        let crossing = topology.cross(0, Edge::Right, 0.5).unwrap();
        let (gx, _) = topology
            .to_global(crossing.display, crossing.x, crossing.y)
            .unwrap();
        assert!(
            gx >= 1920 + ENTRY_INSET,
            "landed at {gx}, not clear of the boundary at 1920"
        );
    }

    #[test]
    fn the_inset_cannot_overshoot_a_narrow_display() {
        // A tiny display must still be landed on, not skipped past.
        let topology = DisplayTopology::new(vec![
            display(0, 0, 0, 1920, 1080, true),
            display(1, 1920, 0, 2, 2, false),
        ]);
        let crossing = topology.cross(0, Edge::Right, 0.5).unwrap();
        assert_eq!(crossing.display, 1);
        assert!((0.0..=1.0).contains(&crossing.x));
        let (gx, gy) = topology.to_global(1, crossing.x, crossing.y).unwrap();
        assert_eq!(topology.at_point(gx, gy), Some(1));
    }

    #[test]
    fn a_display_spanning_two_others_crosses_to_the_one_below_the_pointer() {
        // Display 2 sits above both 0 and 1. Which is "below" depends entirely on
        // where the pointer left; picking the nearest alone would send half of these
        // crossings to the wrong monitor.
        let topology = tee();
        let left_half = topology.cross(2, Edge::Bottom, 0.2).unwrap();
        let right_half = topology.cross(2, Edge::Bottom, 0.9).unwrap();
        assert_eq!(left_half.display, 0, "leaving the left of display 2");
        assert_eq!(right_half.display, 1, "leaving the right of display 2");
    }

    #[test]
    fn crossing_up_from_either_lower_display_reaches_the_one_above() {
        let topology = tee();
        assert_eq!(topology.cross(0, Edge::Top, 0.9).unwrap().display, 2);
        assert_eq!(topology.cross(1, Edge::Top, 0.1).unwrap().display, 2);
    }

    #[test]
    fn crossing_round_trips_through_a_spanning_display() {
        // Down then up must return to the display it started from.
        let topology = tee();
        for along in [0.1_f32, 0.3, 0.7, 0.95] {
            let down = topology.cross(2, Edge::Bottom, along).unwrap();
            let up = topology.cross(down.display, Edge::Top, down.x).unwrap();
            assert_eq!(up.display, 2, "crossing down at {along} did not reverse");
        }
    }

    #[test]
    fn crossing_is_reversible() {
        // Going right then left must return to roughly where it started.
        let topology = side_by_side();
        let out = topology.cross(0, Edge::Right, 0.42).unwrap();
        let back = topology.cross(out.display, Edge::Left, out.y).unwrap();
        assert_eq!(back.display, 0);
        assert!(
            (back.y - 0.42).abs() < 0.01,
            "round trip drifted to {}",
            back.y
        );
    }

    #[test]
    fn crossing_works_vertically() {
        let topology = tee();
        let crossing = topology.cross(0, Edge::Top, 0.5).unwrap();
        assert_eq!(crossing.display, 2);
        // Entering through the bottom of the display above.
        assert!(crossing.y > 0.99, "entered at y={}", crossing.y);
    }

    #[test]
    fn crossing_with_no_neighbour_does_nothing() {
        assert_eq!(side_by_side().cross(0, Edge::Left, 0.5), None);
    }

    #[test]
    fn every_crossing_lands_inside_the_target() {
        // Whatever the arrangement, the pointer must never end up off screen.
        for topology in [side_by_side(), tee(), mixed()] {
            for display in topology.all() {
                for edge in Edge::all() {
                    for along in [0.0, 0.25, 0.5, 0.75, 1.0] {
                        if let Some(crossing) = topology.cross(display.index, edge, along) {
                            assert!(
                                (0.0..=1.0).contains(&crossing.x)
                                    && (0.0..=1.0).contains(&crossing.y),
                                "crossing {edge:?} from {} at {along} left the display: {crossing:?}",
                                display.index
                            );
                            assert!(topology.contains(crossing.display));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn edges_are_detected_within_tolerance() {
        assert_eq!(DisplayTopology::edge_at(0.001, 0.5, 0.01), Some(Edge::Left));
        assert_eq!(
            DisplayTopology::edge_at(0.999, 0.5, 0.01),
            Some(Edge::Right)
        );
        assert_eq!(DisplayTopology::edge_at(0.5, 0.001, 0.01), Some(Edge::Top));
        assert_eq!(
            DisplayTopology::edge_at(0.5, 0.999, 0.01),
            Some(Edge::Bottom)
        );
        assert_eq!(DisplayTopology::edge_at(0.5, 0.5, 0.01), None);
    }

    #[test]
    fn a_corner_resolves_to_a_horizontal_edge() {
        // Deterministic rather than dependent on sub-pixel noise.
        assert_eq!(DisplayTopology::edge_at(0.0, 0.0, 0.01), Some(Edge::Left));
    }

    #[test]
    fn a_vanished_display_falls_back_to_the_primary() {
        // A monitor unplugged mid-session must not strand the viewer.
        let topology = side_by_side();
        assert_eq!(topology.resolve(1), Some(1));

        let after_unplug = DisplayTopology::new(vec![display(0, 0, 0, 1920, 1080, true)]);
        assert_eq!(after_unplug.resolve(1), Some(0));
    }

    #[test]
    fn scale_factor_does_not_disturb_the_arrangement() {
        // A 200% display next to a 100% one: the reported rectangles already account
        // for placement, so adjacency and crossing must be unaffected.
        let topology = DisplayTopology::new(vec![
            DisplayInfo {
                scale_factor: 1.0,
                ..display(0, 0, 0, 1920, 1080, true)
            },
            DisplayInfo {
                scale_factor: 2.0,
                ..display(1, 1920, 0, 3840, 2160, false)
            },
        ]);
        assert_eq!(topology.adjacent(0, Edge::Right), Some(1));
        let crossing = topology.cross(0, Edge::Right, 0.5).unwrap();
        assert_eq!(crossing.display, 1);
        assert!((0.0..=1.0).contains(&crossing.y));
    }

    #[test]
    fn the_virtual_desktop_spans_every_display() {
        let (left, top, right, bottom) = tee().virtual_bounds().unwrap();
        assert_eq!((left, top), (0, -1080));
        assert_eq!((right, bottom), (3840, 1080));
    }

    #[test]
    fn opposite_edges_pair_up() {
        for edge in Edge::all() {
            assert_eq!(edge.opposite().opposite(), edge);
        }
    }

    #[test]
    fn a_single_display_has_no_neighbours_anywhere() {
        let solo = DisplayTopology::new(vec![display(0, 0, 0, 1920, 1080, true)]);
        for edge in Edge::all() {
            assert_eq!(solo.adjacent(0, edge), None);
            assert_eq!(solo.cross(0, edge, 0.5), None);
        }
    }
}
