use async_trait::async_trait;
use std::time::Duration;

use crate::config;
use crate::display::DisplayState;
use rayhunter::analysis::analyzer::EventType;

use log::{error, info};
use tokio::sync::mpsc::Receiver;
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;
use tokio_util::task::TaskTracker;

use include_dir::{Dir, include_dir};

const REFRESH_RATE: u64 = 1000; //how often in milliseconds to refresh the display

#[derive(Copy, Clone)]
pub struct Dimensions {
    pub width: u32,
}

#[derive(Copy, Clone)]
pub enum LinePattern {
    Solid,
    Dashed, // _ _ _ _
    Dotted, // . . . .
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum Color {
    Red,
    Green,
    Blue,
    White,
    Black,
    Cyan,
    Yellow,
    Pink,
    Orange,
}

impl Color {
    fn rgb(self) -> (u8, u8, u8) {
        match self {
            Color::Red => (0xff, 0, 0),
            Color::Green => (0, 0xff, 0),
            Color::Blue => (0, 0, 0xff),
            Color::White => (0xff, 0xff, 0xff),
            Color::Black => (0, 0, 0),
            Color::Cyan => (0, 0xff, 0xff),
            Color::Yellow => (0xff, 0xff, 0),
            Color::Pink => (0xfe, 0x24, 0xff),
            Color::Orange => (0xff, 0xa5, 0),
        }
    }
}

fn display_style_from_state(state: DisplayState, colorblind_mode: bool) -> (Color, LinePattern) {
    match state {
        DisplayState::Paused => (Color::White, LinePattern::Solid),
        DisplayState::Recording => {
            if colorblind_mode {
                (Color::Blue, LinePattern::Solid)
            } else {
                (Color::Green, LinePattern::Solid)
            }
        }
        DisplayState::WarningDetected { event_type } => match event_type {
            EventType::Informational => {
                if colorblind_mode {
                    (Color::Blue, LinePattern::Solid)
                } else {
                    (Color::Green, LinePattern::Solid)
                }
            }
            EventType::Low => (Color::Yellow, LinePattern::Dotted),
            EventType::Medium => (Color::Orange, LinePattern::Dashed),
            EventType::High => (Color::Red, LinePattern::Solid),
        },
    }
}

#[async_trait]
pub trait GenericFramebuffer: Send + 'static {
    fn dimensions(&self) -> Dimensions;

    async fn write_buffer(&mut self, buffer: Vec<(u8, u8, u8)>); // rgb, row-wise, left-to-right, top-to-bottom

    async fn draw_line(&mut self, color: Color, height: u32) {
        self.draw_patterned_line(color, height, LinePattern::Solid)
            .await
    }

    async fn draw_patterned_line(&mut self, color: Color, height: u32, pattern: LinePattern) {
        let width = self.dimensions().width;
        let mut buffer = Vec::new();

        for _row in 0..height {
            for col in 0..width {
                let should_draw = match pattern {
                    LinePattern::Solid => true,
                    LinePattern::Dashed => (col / 4) % 2 == 0, // 4 pixels on, 4 pixels off
                    LinePattern::Dotted => col % 4 == 0,       // 1 pixel on, 3 pixels off
                };

                if should_draw {
                    buffer.push(color.rgb());
                } else {
                    buffer.push((0, 0, 0)); // Black background
                }
            }
        }

        self.write_buffer(buffer).await
    }
}

pub fn update_ui(
    task_tracker: &TaskTracker,
    config: &config::Config,
    mut fb: impl GenericFramebuffer,
    mut ui_shutdown_rx: oneshot::Receiver<()>,
    mut ui_update_rx: Receiver<DisplayState>,
) {
    let display_level = config.ui_level;
    if display_level == 0 {
        info!("Invisible mode, not spawning UI.");
    }

    let colorblind_mode = config.colorblind_mode;
    let mut display_style = display_style_from_state(DisplayState::Recording, colorblind_mode);

    task_tracker.spawn(async move {
        loop {
            match ui_shutdown_rx.try_recv() {
                Ok(_) => {
                    info!("received UI shutdown");
                    break;
                }
                Err(TryRecvError::Empty) => {}
                Err(e) => panic!("error receiving shutdown message: {e}"),
            }
            match ui_update_rx.try_recv() {
                Ok(state) => {
                    display_style = display_style_from_state(state, colorblind_mode);
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
                Err(e) => error!("error receiving framebuffer update message: {e}"),
            }

            match display_level {
                128 => {
                    fb.draw_line(Color::Cyan, 128).await;
                    fb.draw_line(Color::Pink, 102).await;
                    fb.draw_line(Color::White, 76).await;
                    fb.draw_line(Color::Pink, 50).await;
                    fb.draw_line(Color::Cyan, 25).await;
                }
                // this branch id for ui_level 1, which is also the default if an
                // unknown value is used
                _ => {}
            };
            let (color, pattern) = display_style;
            fb.draw_patterned_line(color, 2, pattern).await;
            tokio::time::sleep(Duration::from_millis(REFRESH_RATE)).await;
        }
    });
}
