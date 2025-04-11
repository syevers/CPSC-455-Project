import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * Combines multiple class names or class name arrays into a single string,
 * resolving Tailwind CSS class conflicts.
 *
 * @param inputs - Class names or class name arrays to combine.
 * @returns A string of combined and merged class names.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
