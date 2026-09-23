# Native Login Rounded UI Design

## Goal

Polish the native login window so its input field and action buttons match the approved rounded preview, while preserving the current login, claim, reset, loading, and error behavior.

## Scope

This change is limited to `desktop/native_auth.py` and its UI tests. The browser dashboard, proxy lifecycle, authentication contracts, packaging flow, and `ttk` fallback UI remain unchanged.

## Visual Design

- Keep the existing CustomTkinter implementation and the current light brand palette.
- Apply a consistent medium radius of `12px` to the login input, primary action, secondary recovery action, and the one-time-code dialog controls.
- Keep the checkbox square and native-looking so it remains recognizable as a binary setting.
- Keep the green primary action visually dominant; use the pale green secondary action for recovery and navigation.
- Preserve the existing fixed minimum window size and the current responsive grid so the layout does not jump while error or loading text changes.
- Preserve keyboard behavior: Return submits the active form, Escape returns to login where currently supported, and busy state disables all controls.

## Behavior and Accessibility

- Do not change the `LoginFlow` state transitions or network calls.
- Keep the input focused when a screen opens.
- Keep error text inline below the form and preserve the existing busy progress indicator.
- Keep the visible-input control as a text toggle in this pass; icon-only controls are deferred so the current keyboard and screen-reader behavior stays stable.

## Validation

- Add focused UI contract assertions for the radius and style values.
- Run the focused native-auth tests and the complete desktop test suite.
- Build the macOS application and run the existing packaged smoke test to ensure the CustomTkinter resources remain bundled.
