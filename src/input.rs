//! RDP scan-code/UTF-16 input to RFB X11 keysyms. No native input injection.
use crate::rfb::Input;
use clap::ValueEnum;
use ironrdp_server::{KeyboardEvent, MouseButton, MouseEvent, RdpServerInputHandler};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::{Notify, mpsc};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Keymap {
    #[default]
    Auto,
    Pc,
    Mac,
}

pub fn unicode_keysym(codepoint: u32) -> Option<u32> {
    char::from_u32(codepoint).map(|_| {
        if codepoint <= 255 {
            codepoint
        } else {
            0x0100_0000 | codepoint
        }
    })
}

pub fn scancode(
    code: u8,
    extended: bool,
    shift: bool,
    caps: bool,
    num: bool,
    mac: bool,
) -> Option<u32> {
    if extended {
        return Some(match code {
            0x1c => 0xff8d,
            0x1d => 0xffe4,
            0x35 => u32::from(b'/'),
            0x38 => {
                if mac {
                    0xffea
                } else {
                    0xfe03
                }
            }
            0x47 => 0xff50,
            0x48 => 0xff52,
            0x49 => 0xff55,
            0x4b => 0xff51,
            0x4d => 0xff53,
            0x4f => 0xff57,
            0x50 => 0xff54,
            0x51 => 0xff56,
            0x52 => 0xff63,
            0x53 => 0xffff,
            // macOS Screen Sharing maps Super to Command; Meta is not reliable.
            0x5b => 0xffeb,
            0x5c => 0xffec,
            0x5d => 0xff67,
            _ => return None,
        });
    }
    let letter = match code {
        0x10..=0x19 => Some(b"qwertyuiop"[usize::from(code - 0x10)]),
        0x1e..=0x26 => Some(b"asdfghjkl"[usize::from(code - 0x1e)]),
        0x2c..=0x32 => Some(b"zxcvbnm"[usize::from(code - 0x2c)]),
        _ => None,
    };
    if let Some(c) = letter {
        return Some(u32::from(if shift ^ caps {
            c.to_ascii_uppercase()
        } else {
            c
        }));
    }
    if (0x02..=0x0b).contains(&code) {
        return Some(u32::from(if shift {
            b"!@#$%^&*()"[usize::from(code - 2)]
        } else {
            b"1234567890"[usize::from(code - 2)]
        }));
    }
    let pair = match code {
        0x0c => Some((b'-', b'_')),
        0x0d => Some((b'=', b'+')),
        0x1a => Some((b'[', b'{')),
        0x1b => Some((b']', b'}')),
        0x27 => Some((b';', b':')),
        0x28 => Some((b'\'', b'"')),
        0x29 => Some((b'`', b'~')),
        0x2b => Some((b'\\', b'|')),
        0x33 => Some((b',', b'<')),
        0x34 => Some((b'.', b'>')),
        0x35 => Some((b'/', b'?')),
        _ => None,
    };
    if let Some((a, b)) = pair {
        return Some(u32::from(if shift { b } else { a }));
    }
    Some(match code {
        0x01 => 0xff1b,
        0x0e => 0xff08,
        0x0f => 0xff09,
        0x1c => 0xff0d,
        0x1d => 0xffe3,
        0x2a => 0xffe1,
        0x36 => 0xffe2,
        0x37 => u32::from(b'*'),
        0x38 => 0xffe9,
        0x39 => u32::from(b' '),
        0x3a => 0xffe5,
        0x3b..=0x44 => 0xffbe + u32::from(code - 0x3b),
        0x45 => 0xff7f,
        0x46 => 0xff14,
        0x47 => {
            if num {
                0xffb7
            } else {
                0xff50
            }
        }
        0x48 => {
            if num {
                0xffb8
            } else {
                0xff52
            }
        }
        0x49 => {
            if num {
                0xffb9
            } else {
                0xff55
            }
        }
        0x4a => 0xffad,
        0x4b => {
            if num {
                0xffb4
            } else {
                0xff51
            }
        }
        0x4c => 0xffb5,
        0x4d => {
            if num {
                0xffb6
            } else {
                0xff53
            }
        }
        0x4e => 0xffab,
        0x4f => {
            if num {
                0xffb1
            } else {
                0xff57
            }
        }
        0x50 => {
            if num {
                0xffb2
            } else {
                0xff54
            }
        }
        0x51 => {
            if num {
                0xffb3
            } else {
                0xff56
            }
        }
        0x52 => {
            if num {
                0xffb0
            } else {
                0xff63
            }
        }
        0x53 => {
            if num {
                0xffae
            } else {
                0xffff
            }
        }
        0x57 => 0xffc8,
        0x58 => 0xffc9,
        _ => return None,
    })
}

pub struct Handler {
    tx: mpsc::Sender<Input>,
    fatal: Arc<Notify>,
    read_only: bool,
    mac: bool,
    pressed: BTreeMap<(u8, bool), u32>,
    pending_motion: Option<Weak<Mutex<(u16, u16)>>>,
    caps: bool,
    num: bool,
    surrogate_down: Option<u16>,
    surrogate_up: Option<u16>,
    buttons: u8,
    x: u16,
    y: u16,
    vertical: i32,
    horizontal: i32,
}
impl Handler {
    pub fn new(tx: mpsc::Sender<Input>, fatal: Arc<Notify>, read_only: bool, mac: bool) -> Self {
        Self {
            tx,
            fatal,
            read_only,
            mac,
            pressed: BTreeMap::new(),
            pending_motion: None,
            caps: false,
            num: false,
            surrogate_down: None,
            surrogate_up: None,
            buttons: 0,
            x: 0,
            y: 0,
            vertical: 0,
            horizontal: 0,
        }
    }
    fn send(&mut self, event: Input) {
        // A key/button edge is an ordering barrier for motion coalescing.
        self.pending_motion = None;
        // Never silently drop a key-up: bounded queue exhaustion closes the bridge.
        if !self.read_only && self.tx.try_send(event).is_err() {
            self.fatal.notify_one();
        }
    }
    fn unicode(&mut self, value: u16, down: bool) {
        let pending = if down {
            &mut self.surrogate_down
        } else {
            &mut self.surrogate_up
        };
        let cp = if (0xd800..=0xdbff).contains(&value) {
            *pending = Some(value);
            return;
        } else if (0xdc00..=0xdfff).contains(&value) {
            let Some(high) = pending.take() else {
                return;
            };
            0x10000 + ((u32::from(high) - 0xd800) << 10) + (u32::from(value) - 0xdc00)
        } else {
            *pending = None;
            u32::from(value)
        };
        if let Some(keysym) = unicode_keysym(cp) {
            self.send(Input::Key { down, keysym });
        }
    }
    fn move_pointer(&mut self) {
        if self.read_only {
            return;
        }
        if let Some(position) = self.pending_motion.as_ref().and_then(Weak::upgrade) {
            *position.lock().expect("pointer position lock poisoned") = (self.x, self.y);
            return;
        }
        // At most one queued move per uninterrupted motion run. Critical edges
        // remain ordered; motion alone cannot exhaust the input queue.
        let position = Arc::new(Mutex::new((self.x, self.y)));
        self.pending_motion = Some(Arc::downgrade(&position));
        match self.tx.try_send(Input::PointerMove {
            mask: self.buttons,
            position,
        }) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => self.fatal.notify_one(),
        }
    }
    fn send_pointer(&mut self, mask: u8) {
        self.send(Input::Pointer {
            mask,
            x: self.x,
            y: self.y,
        });
    }
    fn button(&mut self, button: MouseButton, down: bool) {
        let bit = match button {
            MouseButton::Left => 1,
            MouseButton::Middle => 2,
            MouseButton::Right => 4,
            _ => return,
        };
        if down {
            self.buttons |= bit;
        } else {
            self.buttons &= !bit;
        }
        self.send_pointer(self.buttons);
    }
    fn scroll(&mut self, value: i32, horizontal: bool) {
        let accumulator = if horizontal {
            &mut self.horizontal
        } else {
            &mut self.vertical
        };
        *accumulator = accumulator.saturating_add(value).clamp(-3840, 3840);
        let ticks = *accumulator / 120;
        *accumulator %= 120;
        let bit = match (horizontal, ticks > 0) {
            (false, true) => 8,
            (false, false) => 16,
            (true, true) => 64,
            (true, false) => 32,
        };
        for _ in 0..ticks.unsigned_abs() {
            self.send_pointer(self.buttons | bit);
            self.send_pointer(self.buttons);
        }
    }
}
impl RdpServerInputHandler for Handler {
    fn keyboard(&mut self, event: KeyboardEvent) {
        if self.read_only {
            return;
        }
        match event {
            KeyboardEvent::Pressed { code, extended } => {
                if let Some(&keysym) = self.pressed.get(&(code, extended)) {
                    self.send(Input::Key { down: true, keysym });
                    return;
                }
                if code == 0x3a && !extended {
                    self.caps = !self.caps;
                }
                if code == 0x45 && !extended {
                    self.num = !self.num;
                }
                let shift = self.pressed.contains_key(&(0x2a, false))
                    || self.pressed.contains_key(&(0x36, false));
                if let Some(keysym) = scancode(code, extended, shift, self.caps, self.num, self.mac)
                {
                    self.pressed.insert((code, extended), keysym);
                    self.send(Input::Key { down: true, keysym });
                }
            }
            KeyboardEvent::Released { code, extended } => {
                if let Some(keysym) = self.pressed.remove(&(code, extended)) {
                    // Different physical keys (for example Home and keypad 7)
                    // can hold the same RFB keysym. Repeats do not add owners.
                    if !self.pressed.values().any(|&held| held == keysym) {
                        self.send(Input::Key {
                            down: false,
                            keysym,
                        });
                    }
                }
            }
            KeyboardEvent::UnicodePressed(v) => self.unicode(v, true),
            KeyboardEvent::UnicodeReleased(v) => self.unicode(v, false),
            KeyboardEvent::Synchronize(flags) => {
                self.caps = flags.bits() & 4 != 0;
                self.num = flags.bits() & 2 != 0;
            }
        }
    }
    fn mouse(&mut self, event: MouseEvent) {
        if self.read_only {
            return;
        }
        match event {
            MouseEvent::Move { x, y } => {
                self.x = x;
                self.y = y;
                self.move_pointer();
            }
            MouseEvent::Button {
                x,
                y,
                button,
                pressed,
            } => {
                self.x = x;
                self.y = y;
                self.button(button, pressed);
            }
            MouseEvent::ButtonRel {
                x,
                y,
                button,
                pressed,
            } => {
                self.x = i32::from(self.x).saturating_add(x).clamp(0, 65535) as u16;
                self.y = i32::from(self.y).saturating_add(y).clamp(0, 65535) as u16;
                self.button(button, pressed);
            }
            MouseEvent::VerticalScroll { value } => self.scroll(i32::from(value), false),
            MouseEvent::HorizontalScroll { value } => self.scroll(i32::from(value), true),
            MouseEvent::Scroll { x, y } => {
                self.scroll(x, true);
                self.scroll(y, false);
            }
            MouseEvent::RelMove { x, y } => {
                self.x = i32::from(self.x).saturating_add(x).clamp(0, 65535) as u16;
                self.y = i32::from(self.y).saturating_add(y).clamp(0, 65535) as u16;
                self.move_pointer();
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn down_arrow_is_not_up_arrow() {
        assert_eq!(
            scancode(0x50, true, false, false, false, false),
            Some(0xff54)
        );
        assert_eq!(
            scancode(0x48, true, false, false, false, false),
            Some(0xff52)
        );
    }
    #[test]
    fn command_option_and_control_are_distinct() {
        assert_eq!(
            scancode(0x5b, true, false, false, false, true),
            Some(0xffeb)
        );
        assert_eq!(
            scancode(0x38, false, false, false, false, true),
            Some(0xffe9)
        );
        assert_eq!(
            scancode(0x1d, false, false, false, false, true),
            Some(0xffe3)
        );
    }
    #[test]
    fn unicode_including_supplementary_plane() {
        assert_eq!(unicode_keysym('中' as u32), Some(0x01004e2d));
        assert_eq!(unicode_keysym(0x1f600), Some(0x0101f600));
        assert_eq!(unicode_keysym(0xd800), None);
        let (tx, mut rx) = mpsc::channel(8);
        let mut h = Handler::new(tx, Arc::new(Notify::new()), false, true);
        h.keyboard(KeyboardEvent::UnicodePressed(0xd83d));
        h.keyboard(KeyboardEvent::UnicodePressed(0xde00));
        assert!(matches!(
            rx.try_recv(),
            Ok(Input::Key {
                down: true,
                keysym: 0x0101f600
            })
        ));
    }
    #[test]
    fn key_up_uses_the_original_keysym_after_shift_changes() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut h = Handler::new(tx, Arc::new(Notify::new()), false, false);
        for e in [
            KeyboardEvent::Pressed {
                code: 0x2a,
                extended: false,
            },
            KeyboardEvent::Pressed {
                code: 0x1e,
                extended: false,
            },
            KeyboardEvent::Released {
                code: 0x2a,
                extended: false,
            },
            KeyboardEvent::Released {
                code: 0x1e,
                extended: false,
            },
        ] {
            h.keyboard(e);
        }
        for _ in 0..3 {
            rx.try_recv().unwrap();
        }
        assert!(matches!(
            rx.try_recv(),
            Ok(Input::Key {
                down: false,
                keysym: 65
            })
        ));
    }
    #[test]
    fn motion_bursts_coalesce_and_leave_room_for_edges() {
        let (tx, mut rx) = mpsc::channel(256);
        let mut h = Handler::new(tx, Arc::new(Notify::new()), false, false);
        for x in 0..10_000 {
            h.mouse(MouseEvent::Move { x, y: 12 });
        }
        assert_eq!(rx.len(), 1);
        h.keyboard(KeyboardEvent::Pressed {
            code: 0x1e,
            extended: false,
        });
        h.mouse(MouseEvent::Button {
            x: 10_000,
            y: 12,
            button: MouseButton::Left,
            pressed: true,
        });
        h.keyboard(KeyboardEvent::Released {
            code: 0x1e,
            extended: false,
        });
        h.mouse(MouseEvent::Button {
            x: 10_000,
            y: 12,
            button: MouseButton::Left,
            pressed: false,
        });
        let Input::PointerMove { mask, position } = rx.try_recv().unwrap() else {
            panic!("expected coalesced motion");
        };
        assert_eq!(mask, 0);
        assert_eq!(*position.lock().unwrap(), (9_999, 12));
        assert!(matches!(
            rx.try_recv(),
            Ok(Input::Key {
                down: true,
                keysym: 97
            })
        ));
        assert!(matches!(
            rx.try_recv(),
            Ok(Input::Pointer {
                mask: 1,
                x: 10_000,
                y: 12
            })
        ));
        assert!(matches!(
            rx.try_recv(),
            Ok(Input::Key {
                down: false,
                keysym: 97
            })
        ));
        assert!(matches!(
            rx.try_recv(),
            Ok(Input::Pointer {
                mask: 0,
                x: 10_000,
                y: 12
            })
        ));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn motion_coalescing_never_crosses_key_or_button_edges() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut h = Handler::new(tx, Arc::new(Notify::new()), false, false);
        h.mouse(MouseEvent::Move { x: 1, y: 2 });
        h.keyboard(KeyboardEvent::Pressed {
            code: 0x1e,
            extended: false,
        });
        h.mouse(MouseEvent::Move { x: 3, y: 4 });
        h.mouse(MouseEvent::Button {
            x: 5,
            y: 6,
            button: MouseButton::Left,
            pressed: true,
        });
        h.mouse(MouseEvent::Move { x: 7, y: 8 });
        h.mouse(MouseEvent::RelMove { x: 2, y: -2 });
        h.mouse(MouseEvent::Button {
            x: 9,
            y: 6,
            button: MouseButton::Left,
            pressed: false,
        });
        for (mask, expected) in [(0, (1, 2)), (0, (3, 4)), (1, (9, 6))] {
            let Input::PointerMove {
                mask: actual,
                position,
            } = rx.try_recv().unwrap()
            else {
                panic!("expected motion before edge");
            };
            assert_eq!(actual, mask);
            assert_eq!(*position.lock().unwrap(), expected);
            match rx.try_recv().unwrap() {
                Input::Key {
                    down: true,
                    keysym: 97,
                } if expected == (1, 2) => {}
                Input::Pointer {
                    mask: 1,
                    x: 5,
                    y: 6,
                } if expected == (3, 4) => {}
                Input::Pointer {
                    mask: 0,
                    x: 9,
                    y: 6,
                } if expected == (9, 6) => {}
                other => panic!("unexpected edge: {other:?}"),
            }
        }
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn consumed_motion_allows_another_motion_to_queue() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut h = Handler::new(tx, Arc::new(Notify::new()), false, false);
        h.mouse(MouseEvent::Move { x: 1, y: 2 });
        drop(rx.try_recv().unwrap());
        h.mouse(MouseEvent::Move { x: 3, y: 4 });
        let Input::PointerMove { position, .. } = rx.try_recv().unwrap() else {
            panic!("expected a new motion");
        };
        assert_eq!(*position.lock().unwrap(), (3, 4));
    }

    #[tokio::test]
    async fn full_queue_drops_motion_but_never_silently_drops_key_edges() {
        let (tx, mut rx) = mpsc::channel(1);
        let fatal = Arc::new(Notify::new());
        let mut h = Handler::new(tx, fatal.clone(), false, false);
        h.keyboard(KeyboardEvent::Pressed {
            code: 0x1e,
            extended: false,
        });
        h.mouse(MouseEvent::Move { x: 1, y: 2 });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), fatal.notified())
                .await
                .is_err()
        );
        h.keyboard(KeyboardEvent::Released {
            code: 0x1e,
            extended: false,
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), fatal.notified())
            .await
            .unwrap();
        assert!(matches!(
            rx.try_recv(),
            Ok(Input::Key {
                down: true,
                keysym: 97
            })
        ));
        h.mouse(MouseEvent::Move { x: 3, y: 4 });
        assert!(matches!(rx.try_recv(), Ok(Input::PointerMove { .. })));
    }

    #[test]
    fn shared_keysym_releases_only_after_last_scancode_even_with_repeats() {
        for first_release in [false, true] {
            let (tx, mut rx) = mpsc::channel(16);
            let mut h = Handler::new(tx, Arc::new(Notify::new()), false, false);
            // Navigation Home and NumLock-off keypad 7 both map to XK_Home.
            for extended in [false, true, false, true] {
                h.keyboard(KeyboardEvent::Pressed {
                    code: 0x47,
                    extended,
                });
                assert!(matches!(
                    rx.try_recv(),
                    Ok(Input::Key {
                        down: true,
                        keysym: 0xff50
                    })
                ));
            }
            h.keyboard(KeyboardEvent::Released {
                code: 0x47,
                extended: first_release,
            });
            assert!(rx.try_recv().is_err());
            h.keyboard(KeyboardEvent::Pressed {
                code: 0x47,
                extended: !first_release,
            });
            assert!(matches!(
                rx.try_recv(),
                Ok(Input::Key {
                    down: true,
                    keysym: 0xff50
                })
            ));
            h.keyboard(KeyboardEvent::Released {
                code: 0x47,
                extended: !first_release,
            });
            assert!(matches!(
                rx.try_recv(),
                Ok(Input::Key {
                    down: false,
                    keysym: 0xff50
                })
            ));
            h.keyboard(KeyboardEvent::Released {
                code: 0x47,
                extended: !first_release,
            });
            assert!(rx.try_recv().is_err());
        }
    }

    #[test]
    fn read_only_really_blocks_input() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut h = Handler::new(tx, Arc::new(Notify::new()), true, false);
        h.keyboard(KeyboardEvent::UnicodePressed(65));
        h.mouse(MouseEvent::Move { x: 1, y: 2 });
        assert!(rx.try_recv().is_err());
    }
}
