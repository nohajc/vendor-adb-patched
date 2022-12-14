# Pointer Capture in InputFlinger

## Introduction

[Pointer Capture](https://developer.android.com/training/gestures/movement#pointer-capture) is a feature that was introduced to the Android input pipeline in Android 8.0 (Oreo). Pointer Capture can be enabled or disabled for an `InputWindow` through requests to `InputManagerService`. Enabling Pointer Capture performs the following changes related to the mouse cursor and the devices that control it:

- The position of the mouse cursor is fixed to its location before Pointer Capture was enabled.
- The mouse cursor is hidden.
- Events from a mouse will be delivered with the source `SOURCE_MOUSE_RELATIVE`, and their `AXIS_X` and `AXIS_Y` will report relative position changes.
- Events from a touchpad will be delivered with the source `SOURCE_TOUCHPAD`, and their `AXIS_X` and `AXIS_Y` will report the absolute position of each of the pointers on the touchpad.
- Events from mouse and touchpad devices are dispatched to the focused `InputWindow`.
- Events from devices that do not normally control the mouse cursor are not affected.

`InputWindow`s can only gain Pointer Capture if they have window focus. If a window with Pointer Capture loses focus, Pointer Capture is disabled.

## Pointer Capture pipeline in InputFlinger

`InputDispatcher` is responsible for controlling the state of Pointer Capture. Since the feature requires changes to how events are generated, Pointer Capture is configured in `InputReader`.

We use a sequence number to synchronize different requests to enable Pointer Capture between InputReader and InputDispatcher.

### Enabling Pointer Capture

There are four key steps that take place when Pointer Capture is enabled:

1. Requests to enable Pointer Capture are forwarded from `InputManagerService` to `InputDispatcher`.
2. If the window that makes the request has focus, `InputDispatcher` enables the Pointer Capture state in `InputReader` through the `InputDispatcherPolicy`.
3. When `InputReader` is successfully configured, it notifies `InputDispatcher` through the `InputListener` interface.
4. `InputDispatcher` then notifies the `InputWindow` that Pointer Capture has been enabled by sending a special `CAPTURE` event through the `InputChannel`.

### Disabling Pointer Capture

Pointer Capture can be disabled in two ways: by a request through `InputManagerService`, and as a result of the `InputWindow` losing focus.

When Pointer Capture is disabled by a request from the application, it follows the same pipeline as when Pointer Capture is enabled.

#### Window loses Pointer Capture when it loses focus

When an `InputWindow` with Pointer Capture loses focus, Pointer Capture is disabled immediately. The `InputWindow` receives a `CAPTURE` event through the `InputChannel`, followed by a `FOCUS` event to notify loss of focus.

## Pointer Capture in `InputDispatcher`

`InputDispatcher` tracks two pieces of state information regarding Pointer Capture:

- `mCurrentPointerCaptureRequest`: The sequence number of the current Pointer Capture request. This request is enabled iff the focused window has requested Pointer Capture. This is updated whenever the Dispatcher receives requests from `InputManagerService`.
- `mWindowTokenWithPointerCapture`: The Binder token of the `InputWindow` that currently has Pointer Capture. This is only updated during the dispatch cycle. If it is not `nullptr`, it signifies that the window was notified that it has Pointer Capture.
