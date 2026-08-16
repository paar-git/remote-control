import { isTauriAvailable } from '../ipc.js';

export async function minimizeWindow(): Promise<void> {
  if (!isTauriAvailable()) return;
  const { getCurrentWindow } = await import('@tauri-apps/api/window');
  await getCurrentWindow().minimize();
}

export async function toggleMaximizeWindow(): Promise<void> {
  if (!isTauriAvailable()) return;
  const { getCurrentWindow } = await import('@tauri-apps/api/window');
  await getCurrentWindow().toggleMaximize();
}

export async function closeWindow(): Promise<void> {
  if (!isTauriAvailable()) return;
  const { getCurrentWindow } = await import('@tauri-apps/api/window');
  await getCurrentWindow().close();
}

export async function isWindowMaximized(): Promise<boolean> {
  if (!isTauriAvailable()) return false;
  const { getCurrentWindow } = await import('@tauri-apps/api/window');
  return getCurrentWindow().isMaximized();
}

export async function listenWindowMaximized(
  onChange: (maximized: boolean) => void,
): Promise<() => void> {
  if (!isTauriAvailable()) return () => undefined;
  const { getCurrentWindow } = await import('@tauri-apps/api/window');
  const win = getCurrentWindow();
  const sync = async (): Promise<void> => {
    onChange(await win.isMaximized());
  };
  const unResized = await win.onResized(() => {
    void sync();
  });
  const unMoved = await win.onMoved(() => {
    void sync();
  });
  await sync();
  return () => {
    unResized();
    unMoved();
  };
}
