import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { ConnectionState } from '../api.js';
import * as api from '../api.js';
import { ConnectionBar } from './ConnectionBar';
import { useConnectForm } from '../useConnectForm.js';

vi.mock('../api.js', async (importOriginal) => {
  const actual: typeof api = await importOriginal();
  return {
    ...actual,
    connectToAddress: vi.fn(() => Promise.resolve({ state: 'connecting', address: 'x' })),
    getConnectionState: vi.fn(),
  };
});

function Harness({
  connection = { state: 'offline' },
}: {
  readonly connection?: ConnectionState;
}): React.JSX.Element {
  const form = useConnectForm({
    connection,
    onConnection: vi.fn(),
    onToast: vi.fn(),
  });
  return (
    <ConnectionBar
      address={form.address}
      onAddressChange={form.setAddress}
      onSubmit={form.submit}
      parseError={form.parseError}
      busy={form.busy}
      failed={form.failed}
      connection={connection}
      recent={[]}
      inputRef={form.inputRef}
      onPickRecent={form.connect}
      onConnectWithPassword={form.submitWithPassword}
      onNavigate={vi.fn()}
    />
  );
}

describe('ConnectionBar', () => {
  beforeEach(() => {
    vi.mocked(api.connectToAddress).mockReset();
    vi.mocked(api.connectToAddress).mockResolvedValue({ state: 'connecting', address: 'x' });
  });

  it('makes connecting the primary action and does not colour it as a warning', () => {
    render(<Harness />);
    const connect = screen.getByRole('button', { name: 'Connect' });
    expect(connect.className).not.toContain('--color-danger');
  });

  it('connects to the address that was typed', async () => {
    const connectToAddress = vi.mocked(api.connectToAddress);
    render(<Harness />);

    await userEvent.type(screen.getByLabelText('Enter remote address'), '192.168.1.77');
    await userEvent.click(screen.getByRole('button', { name: 'Connect' }));

    expect(connectToAddress).toHaveBeenCalledWith('192.168.1.77:7443', null);
  });

  it('does not treat a device id as an address', async () => {
    render(<Harness />);

    await userEvent.type(screen.getByLabelText('Enter remote address'), '842 391 552');
    await userEvent.click(screen.getByRole('button', { name: 'Connect' }));

    expect(vi.mocked(api.connectToAddress)).not.toHaveBeenCalled();
    expect(screen.getByText(/no directory/i)).toBeInTheDocument();
  });

  it('shows progress while the connection is being made rather than appearing inert', () => {
    render(<Harness connection={{ state: 'connecting', address: '192.168.1.77:7443' }} />);

    expect(screen.getByRole('status')).toHaveTextContent(
      'Finding the device at 192.168.1.77:7443…',
    );
    expect(screen.getByRole('button', { name: 'Connecting…' })).toBeDisabled();
  });

  it('sends an unattended password when one is provided', async () => {
    const connectToAddress = vi.mocked(api.connectToAddress);
    render(<Harness />);

    await userEvent.type(screen.getByLabelText('Enter remote address'), '192.168.1.77');
    await userEvent.click(screen.getByRole('button', { name: 'Connect options' }));
    await userEvent.click(screen.getByRole('menuitem', { name: 'Connect with password…' }));
    await userEvent.type(screen.getByLabelText('Password'), 'correct horse');
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Connect' }));

    expect(connectToAddress).toHaveBeenCalledWith('192.168.1.77:7443', 'correct horse');
  });

  it('reports a refusal in a way that says what to do about it', () => {
    render(
      <Harness
        connection={{
          state: 'refused',
          reason: 'identity_changed',
          message: 'That machine is not the one you trusted.',
        }}
      />,
    );

    expect(screen.getByRole('alert')).toHaveTextContent('That machine is not the one you trusted.');
  });
});
