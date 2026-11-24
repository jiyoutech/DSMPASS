export async function copyOrSelect(
  value: string,
  selectManually: () => void,
  clipboard: Pick<Clipboard, "writeText"> | undefined = navigator.clipboard
): Promise<boolean> {
  if (clipboard) {
    try {
      await clipboard.writeText(value);
      return true;
    } catch {
      // Browsers may expose the API but deny this origin clipboard access.
    }
  }
  selectManually();
  return false;
}
