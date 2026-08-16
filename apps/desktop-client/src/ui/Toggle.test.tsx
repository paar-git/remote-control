import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { Toggle } from './Toggle';

describe('Toggle', () => {
  it('moves the thumb to the on position when checked', () => {
    render(<Toggle label="Allow incoming connections" checked onChange={vi.fn()} />);
    const thumb = screen.getByRole('switch').querySelector('span');
    expect(thumb?.className).toContain('translate-x-5');
    expect(thumb?.className).not.toContain('translate-x-0.5');
  });

  it('moves the thumb to the off position when unchecked', () => {
    render(<Toggle label="Allow incoming connections" checked={false} onChange={vi.fn()} />);
    const thumb = screen.getByRole('switch').querySelector('span');
    expect(thumb?.className).toContain('translate-x-0.5');
    expect(thumb?.className).not.toContain('translate-x-5');
  });

  it('reports the opposite value when pressed', async () => {
    const onChange = vi.fn();
    render(<Toggle label="Allow incoming connections" checked onChange={onChange} />);
    await userEvent.click(screen.getByRole('switch'));
    expect(onChange).toHaveBeenCalledWith(false);
  });
});
