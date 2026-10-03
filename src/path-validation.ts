import path from 'path';

/**
 * Checks if an absolute path is within any of the allowed paths.
 * 
 * @param absolutePath - The absolute path to check (will be normalized)
 * @param allowedPaths - Array of absolute normalized allowed paths
 * @param readOnlyPaths - Array of absolute normalized read-only paths
 * @param forbiddenPaths - Array of absolute normalized forbidden paths
 * @returns true if the path is within an allowed directory, false otherwise
 * @throws Error if given relative paths after normalization
 */
export function isPathAllowed(
  absolutePath: string,
  allowedPaths: Iterable<string>,
  readOnlyPaths: Iterable<string>,
  forbiddenPaths: Iterable<string>,
  readOnly: boolean
): boolean | null {
  // Type validation
  if (typeof absolutePath !== 'string')
    return null;

  if (readOnly)
    allowedPaths = [...allowedPaths, ...readOnlyPaths];
  else
    forbiddenPaths = [...readOnlyPaths, ...forbiddenPaths];
  // Reject empty inputs
  if (!absolutePath)
    return null;

  // Reject null bytes (forbidden in paths)
  if (absolutePath.includes('\x00'))
    return null;

  // Normalize the input path
  let normalizedPath: string;
  try {
    normalizedPath = path.resolve(path.normalize(absolutePath));
  } catch {
    return null;
  }

  // Verify it's absolute after normalization
  if (!path.isAbsolute(normalizedPath)) {
    throw new Error('Path must be absolute after normalization');
  }

  for (const p of forbiddenPaths) {
    if (p.endsWith(path.sep)) {
      if (normalizedPath.startsWith(p))
        return false;
    } else if (normalizedPath === p)
      return false;
    else if (normalizedPath.startsWith(p + path.sep))
      return false;
  }

  // Check against each allowed directory
  for (const p of allowedPaths) {
    if (typeof p !== 'string' || !p)
      continue;

    // Reject null bytes in allowed dirs
    if (p.includes('\x00'))
      continue;

    // Check if normalizedPath is within normalizedDir
    // Path is inside if it's the same or a subdirectory
    if (normalizedPath === p)
      return true;

    // Special case for root directory to avoid double slash
    // On Windows, we need to check if both paths are on the same drive
    if (p === path.sep) {
      if (normalizedPath.startsWith(path.sep))
        return true;
      continue;
    }

    // On Windows, also check for drive root (e.g., "C:\")
    if (path.sep === '\\' && p.match(/^[A-Za-z]:\\?$/)) {
      // Ensure both paths are on the same drive
      const dirDrive = p.charAt(0).toLowerCase();
      const pathDrive = normalizedPath.charAt(0).toLowerCase();
      if (pathDrive === dirDrive && normalizedPath.startsWith(p.replace(/\\?$/, '\\')))
        return true;
      continue;
    }

    if (normalizedPath.startsWith(p + path.sep))
      return true;
  };
  return null;
}
