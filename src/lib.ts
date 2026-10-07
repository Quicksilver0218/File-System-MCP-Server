import fs from 'fs/promises';
import path from 'path';
import { createReadStream } from 'fs';
import { ExecException, execFile } from 'child_process';
import { promisify } from 'util';
import { randomBytes } from 'crypto';
import { minimatch } from 'minimatch';
import { normalizePath, expandHome } from './path-utils.js';
import { isPathAllowed } from './path-validation.js';

// Global allowed paths - set by the main module
let allowedPaths = new Set<string>();
let readOnlyPaths = new Set<string>();
let forbiddenPaths = new Set<string>();

// Function to set allowed paths from the main module
export function setAllowedPaths(paths: Iterable<string>) {
  allowedPaths = new Set(paths);
}

export function setReadOnlyPaths(paths: Iterable<string>) {
  readOnlyPaths = new Set(paths);
}

export function setForbiddenPaths(paths: Iterable<string>) {
  forbiddenPaths = new Set(paths);
}

// Type definitions
interface FileInfo {
  size: number;
  created: Date;
  modified: Date;
  accessed: Date;
  isDirectory: boolean;
  isFile: boolean;
  permissions: string;
}

export interface SearchOptions {
  excludePatterns?: string[];
}

export interface SearchResult {
  path: string;
  isDirectory: boolean;
}

// Pure Utility Functions
export function formatSize(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  if (bytes <= 0) return '0 B';

  const i = Math.floor(Math.log(bytes) / Math.log(1024));

  if (i < 0 || i === 0) return `${bytes} ${units[0]}`;

  const unitIndex = Math.min(i, units.length - 1);
  return `${(bytes / Math.pow(1024, unitIndex)).toFixed(2)} ${units[unitIndex]}`;
}

export function normalizeLineEndings(text: string): string {
  return text.replace(/\r\n/g, '\n');
}

// Helper function to resolve relative paths against allowed directories
async function resolveRelativePathAgainstAllowedDirectories(relativePath: string, readOnly: boolean) {
  let paths = [...allowedPaths, ...readOnlyPaths];
  const predicates = await Promise.all(paths.map(async path => {
    try {
      return (await fs.stat(path)).isDirectory();
    } catch {
      return false;
    }
  }));
  paths = paths.filter((_, i) => predicates[i]);
  if (paths.length === 0) {
    // Fallback to process.cwd() if no allowed directories are set
    return path.resolve(process.cwd(), relativePath);
  }

  // Try to resolve relative path against each allowed directory
  for (const allowedDir of paths) {
    const candidate = path.resolve(allowedDir, relativePath);
    const normalizedCandidate = normalizePath(candidate);

    // Check if the resulting path lies within any allowed directory
    if (isPathAllowed(normalizedCandidate, allowedPaths, readOnlyPaths, forbiddenPaths, readOnly)) {
      return candidate;
    }
  }

  // If no valid resolution found, use the first allowed directory as base
  // This provides a consistent fallback behavior
  return path.resolve(allowedPaths.values().next().value!, relativePath);
}

// Security & Validation Functions
async function resolveUnicodeEquivalentPath(absolutePath: string): Promise<string> {
  const paths = [...allowedPaths]
    .sort((left, right) => right.length - left.length)
    .find(directory => isPathAllowed(normalizePath(absolutePath), [directory], readOnlyPaths, forbiddenPaths, false));

  if (!paths) {
    return absolutePath;
  }

  let currentPath = await fs.realpath(paths);
  const relativeParts = path.relative(paths, absolutePath).split(path.sep).filter(Boolean);

  for (let index = 0; index < relativeParts.length; index++) {
    const requestedPart = relativeParts[index];
    const entries = (await fs.readdir(currentPath)) ?? [];
    const exactMatch = entries.find(entry => entry === requestedPart);
    const equivalentMatches = exactMatch
      ? [exactMatch]
      : entries.filter(entry => entry.normalize('NFC') === requestedPart.normalize('NFC'));

    if (equivalentMatches.length > 1) {
      throw new Error(`Ambiguous Unicode path component: ${requestedPart}`);
    }

    if (equivalentMatches.length === 0) {
      // Nothing below this point exists yet, so there are no symlinks left to
      // resolve. currentPath is already realpath'd and inside an allowed
      // directory; append the missing tail so create_directory can mkdir -p it.
      return path.join(currentPath, ...relativeParts.slice(index));
    }

    currentPath = await fs.realpath(path.join(currentPath, equivalentMatches[0]));
    if (!isPathAllowed(normalizePath(currentPath), allowedPaths, readOnlyPaths, forbiddenPaths, false)) {
      throw new Error(`Access denied - symlink target outside allowed paths: ${currentPath} not in ${[...allowedPaths].join(', ')}`);
    }
  }

  return currentPath;
}

export async function validatePath(requestedPath: string, readOnly: boolean): Promise<string> {
  const expandedPath = expandHome(requestedPath);
  // Do not silently reinterpret a Windows drive path as a relative POSIX path.
  // This would create a literal filename such as `C:\\Users\\...` inside the
  // allowed root and report success for the wrong location.
  if (process.platform !== 'win32' && /^(?:[A-Za-z]:)(?:[\\/]|$)/.test(expandedPath)) {
    throw new Error(`Access denied - Windows-style path received on a POSIX host: ${requestedPath}`);
  }
  const absolute = path.isAbsolute(expandedPath)
    ? path.resolve(expandedPath)
    : await resolveRelativePathAgainstAllowedDirectories(expandedPath, readOnly);

  const normalizedRequested = normalizePath(absolute);

  // Security: Check if path is within allowed paths before any file operations
  const isAllowed = isPathAllowed(normalizedRequested, allowedPaths, readOnlyPaths, forbiddenPaths, readOnly);
  if (isAllowed === null)
    throw new Error(`Access denied - path outside allowed paths: ${absolute} not in ${[...allowedPaths].join(', ')}`);
  else if (!isAllowed)
    throw new Error(`Access denied - path inside forbidden paths: ${absolute} in ${[...forbiddenPaths].join(', ')}`);

  // Security: Handle symlinks by checking their real path to prevent symlink attacks
  // This prevents attackers from creating symlinks that point outside allowed paths
  try {
    const realPath = await fs.realpath(absolute);
    const normalizedReal = normalizePath(realPath);
    const isAllowed = isPathAllowed(normalizedReal, allowedPaths, readOnlyPaths, forbiddenPaths, readOnly);
    if (isAllowed === null)
      throw new Error(`Access denied - symlink target outside allowed paths: ${realPath} not in ${[...allowedPaths].join(', ')}`);
    else if (!isAllowed)
      throw new Error(`Access denied - symlink target inside forbidden paths: ${realPath} in ${[...forbiddenPaths].join(', ')}`);
    return realPath;
  } catch (error) {
    // Security: For new files that don't exist yet, verify parent directory
    // This ensures we can't create files in unauthorized locations
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      try {
        return await resolveUnicodeEquivalentPath(absolute);
      } catch (resolutionError) {
        if ((resolutionError as NodeJS.ErrnoException).code === 'ENOENT') {
          throw new Error(`Parent directory does not exist: ${path.dirname(absolute)}`, { cause: resolutionError });
        }
        throw resolutionError;
      }
    }
    throw error;
  }
}


// File Operations
export async function getFileStats(filePath: string): Promise<FileInfo> {
  const stats = await fs.stat(filePath);
  return {
    size: stats.size,
    created: stats.birthtime,
    modified: stats.mtime,
    accessed: stats.atime,
    isDirectory: stats.isDirectory(),
    isFile: stats.isFile(),
    permissions: stats.mode.toString(8).slice(-3),
  };
}

export async function readFileContent(filePath: string, encoding: string = 'utf-8'): Promise<string> {
  return await fs.readFile(filePath, encoding as BufferEncoding);
}

export interface FileReadResult extends Record<string, unknown> {
  fileSize: number;
  totalLines: number;
  lineEnding?: '\r' | '\n' | '\r\n' | 'Mixed';
  truncatedAt?: {
    line: number;
    col: number;
    lineLength: number;
  };
  next?: {
    startLine: number;
    startCol: number;
  };
  note?: string;
  lines: string[];
}

export async function readFile(
  filePath: string,
  options: { startLine?: number; endLine?: number, startCol?: number; maxSize?: number } = {}
): Promise<FileReadResult> {
  const { startLine = 1, endLine, startCol, maxSize = 25000 } = options;
  if (endLine && endLine < startLine)
    throw new Error('endLine must be greater than or equal to startLine');

  const fileHandle = await fs.open(filePath, 'r');
  try {
    let pendingLine = '';
    const chunk = Buffer.alloc(65536); // 64 KB buffer
    const decoder = new TextDecoder();
    let offset = 0;
    let lineCount = 1;
    let lineEnding: '\r' | '\n' | '\r\n' | 'Mixed' | undefined;
    let textLength = 0;
    let truncatedAt: Record<string, number> | undefined;
    let truncated = false;
    const notes = [];
    const lines = [];

    // Read chunks and count lines until we have enough or reach EOF
    let lineLength = 0;
    while (true) {
      const result = await fileHandle.read(chunk, 0, chunk.length, offset);
      if (result.bytesRead === 0) break; // End of file
      const bytes = chunk.subarray(0, result.bytesRead);
      if (!offset) {
        const nullPos = bytes.indexOf(0);
        if (nullPos !== -1)
          notes.push(`The file appears to be binary (NUL byte found at offset ${nullPos}); the text may be garbled - use read_media_file for images or audio.`);
      }
      const text = decoder.decode(bytes);

      let chunkLineCount = 0;
      let firstLineBreakPos, lastLineBreakPos;
      for (let i = 0; i < text.length; i++)
        if (text[i] === '\n' && text[i - 1] !== '\r' || text[i] === '\r') {
          chunkLineCount++;
          if (firstLineBreakPos === undefined)
            firstLineBreakPos = i;
          lastLineBreakPos = i;
        }
      let remainingText;
      if (chunkLineCount) {
        if (lineCount + chunkLineCount > startLine && (!endLine || lineCount <= endLine) && textLength < maxSize) {
          const completeLines = (pendingLine + text.slice(0, lastLineBreakPos)).split(/(\r\n|\r|\n)/);
          for (let i = 0; i < completeLines.length; i++) {
            if (i & 1) {
              if (lineEnding !== 'Mixed')
                if (lineEnding) {
                  if (completeLines[i] !== lineEnding)
                    lineEnding = 'Mixed';
                } else
                  lineEnding = completeLines[i] as '\r' | '\n' | '\r\n';
            } else {
              let line = completeLines[i];
              if (lineCount >= startLine && (!endLine || lineCount <= endLine) && textLength < maxSize) {
                lineLength = line.length;
                let colOffset;
                if (lineCount === startLine && startCol) {
                  line = line.slice(startCol);
                  colOffset = startCol;
                } else
                  colOffset = 0;
                if (textLength + line.length > maxSize) {
                  line = line.slice(0, maxSize - textLength);
                  truncatedAt = {
                    line: lineCount,
                    col: colOffset + line.length,
                    lineLength,
                    nextLine: lineCount,
                    nextCol: colOffset + line.length,
                  };
                  truncated = true;
                } else if (textLength + line.length === maxSize) {
                  truncatedAt = {
                    line: lineCount,
                    col: colOffset + line.length,
                    lineLength,
                    nextLine: lineCount + 1,
                    nextCol: 0,
                  };
                  truncated = true;
                }
                lines.push(line);
                textLength += line.length;
              }
              lineCount++;
            }
          }
        } else {
          if (textLength >= maxSize && !truncated) {
            lineLength += firstLineBreakPos!;
            if (truncatedAt)
              truncatedAt.lineLength = lineLength;
            else {
              let col = pendingLine.length;
              if (lineCount === startLine && startCol)
                col += startCol;
              truncatedAt = {
                line: lineCount,
                col,
                lineLength,
              };
              if (firstLineBreakPos) {
                truncatedAt.nextLine = lineCount;
                truncatedAt.nextCol = col;
              } else {
                truncatedAt.nextLine = lineCount + 1;
                truncatedAt.nextCol = 0;
              }
            }
            truncated = true;
          }
          lineCount += chunkLineCount;
        }
        remainingText = text.slice(lastLineBreakPos! + 1).replace('\n', '');
        lineLength = remainingText.length;
      } else {
        remainingText = text;
        lineLength += text.length;
      }

      let colOffset;
      if (lineCount === startLine && startCol)
        colOffset = startCol;
      else
        colOffset = 0;
      if (lineCount >= startLine && (!endLine || lineCount <= endLine) && !truncatedAt) {
        if (chunkLineCount)
          pendingLine = remainingText;
        else
          pendingLine += remainingText;
        textLength += remainingText.length;
        if (textLength > maxSize + colOffset) {
          pendingLine = pendingLine.slice(colOffset, maxSize + colOffset - textLength);
          lines.push(pendingLine);
          truncatedAt = {
            line: lineCount,
            col: colOffset + pendingLine.length,
            nextLine: lineCount,
            nextCol: colOffset + pendingLine.length,
          };
        }
      }
      offset += result.bytesRead;
    }

    if (truncatedAt) {
      if (!truncated)
        truncatedAt.lineLength = lineLength;
    } else if (lineCount >= startLine && (!endLine || lineCount <= endLine)) {
      // If there is leftover content and we still need lines, add it
      if (lineCount === startLine && startCol)
        lines.push(pendingLine.slice(startCol));
      else
        lines.push(pendingLine);
    }

    const result: FileReadResult = {
      fileSize: offset,
      totalLines: lineCount,
      lines
    };
    if (lineEnding)
      result.lineEnding = lineEnding;
    if (truncatedAt) {
      result.truncatedAt = {
        line: truncatedAt.line,
        col: truncatedAt.col,
        lineLength: truncatedAt.lineLength!
      };
      result.next = {
        startLine: truncatedAt.nextLine,
        startCol: truncatedAt.nextCol
      };
    }
    if (startLine > lineCount)
      notes.push(`startLine (${startLine}) is greater than totalLines (${lineCount}).`);
    if (notes.length)
      result.note = notes.join('\n');
    return result;
  } finally {
    await fileHandle.close();
  }
}

// Reads a file as a stream of buffers, concatenates them, and then encodes
// the result to a Base64 string. This is a memory-efficient way to handle
// binary data from a stream before the final encoding.
export async function readFileAsBase64Stream(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const stream = createReadStream(filePath);
    const chunks: Buffer[] = [];
    stream.on('data', (chunk) => {
      chunks.push(chunk as Buffer);
    });
    stream.on('end', () => {
      const finalBuffer = Buffer.concat(chunks);
      resolve(finalBuffer.toString('base64'));
    });
    stream.on('error', (err) => reject(err));
  });
}

export interface FileEditResult {
  diff: string;
  note?: string;
}

interface FileEdit {
  oldText?: string;
  newText?: string;
  startLine?: number;
  startCol?: number;
}

export async function editFile(
  filePath: string,
  edits: FileEdit[],
  dryRun?: boolean
): Promise<FileEditResult> {
  const stat = await fs.stat(filePath);
  if (!stat.isFile())
    throw new Error(`File (${filePath}) does not exist or is not a file`);
  edits.sort((a, b) => (b.startLine ?? 1) - (a.startLine ?? 1) || (b.startCol ?? 0) - (a.startCol ?? 0));
  const fileHandle = await fs.open(filePath, 'r');
  let outFileSuffix = 0;
  try {
    while (true) {
      await fs.access(`${filePath}${outFileSuffix}`, fs.constants.F_OK);
      outFileSuffix++;
    }
  } catch { }
  let outFileHandle;
  try {
    const chunk = Buffer.alloc(65536); // 64 KB buffer
    const decoder = new TextDecoder();
    outFileHandle = await fs.open(`${filePath}${outFileSuffix}`, 'a');

    const notes = [];

    const readResult = await fileHandle.read(chunk, 0, chunk.length, 0);
    const bytes = chunk.subarray(0, readResult.bytesRead);
    const nullPos = bytes.indexOf(0);
    if (nullPos !== -1)
      notes.push(`The file appears to be binary (NUL byte found at offset ${nullPos}); the text may be garbled.`);
    let lastText = decoder.decode(bytes);
    let offset = readResult.bytesRead;
    let lineCount = 1;
    let lastCol = 0;
    const replacements = [];
    let startPos = 0;
    while (true) {
      const result = await fileHandle.read(chunk, 0, chunk.length, offset);
      const bytes = chunk.subarray(0, result.bytesRead);
      const text = decoder.decode(bytes);
      const fullText = lastText + text;
      const tokens = lastText.split(/(\r\n|\r|\n)/);
      const tokensLineCount = tokens.length / 2 | 0;
      let outText = '';
      if (lineCount + tokensLineCount >= (edits[0]?.startLine ?? 1)) {
        let remainingText = fullText;
        let slicedLen = 0;
        for (let i = 0; i < tokens.length - 1 || i < tokens.length && !result.bytesRead; i += 2) {
          for (let j = edits.length - 1; j >= 0; j--) {
            if (lineCount < (edits[j].startLine ?? 1))
              break;
            let startCol = lineCount === (edits[j].startLine ?? 1) ? Math.max(0, (edits[j].startCol ?? 0) - lastCol) : 0;
            if (lineCount === (edits[j].startLine ?? 1)) {
              startCol = (edits[j].startCol ?? 0) - lastCol;
              if (startCol < 0)
                startCol = 0;
              else if (startCol > tokens[i].length && (tokens[i + 1] || !result.bytesRead))
                startCol = tokens[i].length;
            } else
              startCol = 0;
            const throwError = (replacement: { edit: FileEdit }) => {
              throw new Error(`Edit ${JSON.stringify(edits[j])} overlaps with ${JSON.stringify(replacement.edit)}`)
            };
            if (edits[j].oldText) {
              const match = remainingText.slice(startCol).match(new RegExp(RegExp.escape(edits[j].oldText!)
                .split('\\\\').map(part => part.replaceAll(/\\r\\n|\\r|\\n/ig, '(?:\\r\\n|\\r|\\n)')).join('\\\\')));
              if (match) {
                const startPos = slicedLen + startCol + match.index!;
                const endPos = startPos + match[0].length;
                let inserted = false;
                if (replacements.length)
                  for (let k = 0; k < replacements.length; k++)
                    if (startPos >= replacements[k].startPos) {
                      if (startPos < replacements[k].endPos)
                        throwError(replacements[k]);
                      replacements.splice(k, 0, { edit: edits[j], startPos, endPos });
                      inserted = true;
                      break;
                    }
                if (!inserted) {
                  if (replacements.length && endPos > replacements[replacements.length - 1].startPos)
                    throwError(replacements[replacements.length - 1]);
                  replacements.push({ edit: edits[j], startPos, endPos });
                }
                edits.splice(j, 1);
              }
            } else {
              if (edits[j].newText) {
                const startPos = slicedLen + startCol;
                let inserted = false;
                if (replacements.length)
                  for (let k = 0; k < replacements.length; k++)
                    if (startPos > replacements[k].startPos) {
                      if (startPos < replacements[k].endPos)
                        throwError(replacements[k]);
                      replacements.splice(k, 0, { edit: edits[j], startPos, endPos: startPos });
                      inserted = true;
                      break;
                    }
                if (!inserted)
                  replacements.push({ edit: edits[j], startPos, endPos: startPos });
              }
              edits.splice(j, 1);
            }
          }
          if (!tokens[i + 1])
            break;
          const consumed = tokens[i].length + tokens[i + 1].length;
          remainingText = remainingText.slice(consumed);
          slicedLen += consumed;
          lineCount++;
          lastCol = 0;
        }
        for (let i = replacements.length - 1; i >= 0; i--) {
          if (replacements[i].startPos <= lastText.length) {
            outText += fullText.slice(startPos, replacements[i].startPos) + (replacements[i].edit.newText ?? '');
            startPos = replacements[i].endPos;
            replacements.splice(i, 1);
          } else
            break;
        }
        for (const replacement of replacements) {
          replacement.startPos -= lastText.length;
          replacement.endPos -= lastText.length;
        }
        if (startPos < lastText.length) {
          outText += lastText.slice(startPos);
          startPos = 0;
        } else
          startPos -= lastText.length;
      } else {
        lineCount += tokensLineCount;
        outText = lastText;
        startPos = 0;
      }
      await outFileHandle.appendFile(outText);

      if (result.bytesRead === 0) break; // End of file
      offset += result.bytesRead;

      if (tokens.length > 1) {
        if (outText.endsWith('\r') && text.startsWith('\n'))
          lineCount--;
        lastCol = tokens[tokens.length - 1].length;
      } else
        lastCol += lastText.length;
      lastText = text;
    }

    await fileHandle.close();
    await outFileHandle.close();
    let output: FileEditResult;
    try {
      const { stdout } = await promisify(execFile)(
        process.env.GIT_PATH ?? 'git',
        ['diff', '--no-index', filePath, `${filePath}${outFileSuffix}`]
      );
      output = { diff: stdout.slice(stdout.indexOf('@@')) };
    } catch (e) {
      if ((e as ExecException).code === 1) {
        const stdout = (e as { stdout: string }).stdout;
        output = { diff: stdout.slice(stdout.indexOf('@@')) };
      } else
        output = { diff: 'File comparison is not available.' + dryRun ? '' : ' Read the file to see the changes.' };
    }

    if (!dryRun) {
      await fs.rename(filePath, `${filePath}.bak`);
      try {
        await fs.rename(`${filePath}${outFileSuffix}`, filePath);
        try {
          await fs.chmod(filePath, stat.mode & 0o777);
        } catch { }
        try {
          await fs.rm(`${filePath}.bak`);
        } catch { }
      } catch (e) {
        await fs.rename(`${filePath}.bak`, filePath);
        throw e;
      }
    }

    if (edits.length)
      notes.push(`${edits.length} edits were not applied because the oldTexts were not found in the file.`);
    if (notes.length)
      output.note = notes.join('\n');
    return output;
  } finally {
    await fileHandle.close();
    if (outFileHandle) {
      await outFileHandle.close();
      await fs.rm(`${filePath}${outFileSuffix}`, { force: true });
    }
  }
}

export async function writeFileContent(filePath: string, content: string): Promise<void> {
  try {
    // Security: 'wx' flag ensures exclusive creation - fails if file/symlink exists,
    // preventing writes through pre-existing symlinks
    await fs.writeFile(filePath, content, { encoding: 'utf-8', flag: 'wx' });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
      // Security: Use atomic rename to prevent race conditions where symlinks
      // could be created between validation and write. Rename operations
      // replace the target file atomically and don't follow symlinks.
      const origStats = await fs.stat(filePath);
      const tempPath = `${filePath}.${randomBytes(16).toString('hex')}.tmp`;
      try {
        await fs.writeFile(tempPath, content, 'utf-8');
        await fs.rename(tempPath, filePath);
      } catch (renameError) {
        try {
          await fs.unlink(tempPath);
        } catch { }
        throw renameError;
      }
      // Restore original permission bits since the atomic rename replaces the
      // inode and the temp file has default (0644) permissions. Mask off the
      // file-type bits; POSIX leaves them unspecified for chmod. A chmod
      // failure must not fail the write, which has already succeeded.
      try {
        await fs.chmod(filePath, origStats.mode & 0o777);
      } catch { }
    } else {
      throw error;
    }
  }
}


export async function moveFile(sourcePath: string, destinationPath: string): Promise<void> {
  // The move_file tool contract (and README) state the operation fails if the
  // destination already exists. fs.rename would silently overwrite it, which is
  // a data-loss bug, so reject up front when anything - file, directory, or
  // symlink - occupies the target. lstat is used so an existing symlink at the
  // destination is detected rather than followed.
  try {
    await fs.lstat(destinationPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      await fs.rename(sourcePath, destinationPath);
      return;
    }
    throw error;
  }
  throw new Error(`Destination already exists: ${destinationPath}`);
}

export interface TextSearchResult {
  results: { line: number; col: number; text: string }[];
  end: boolean;
  note?: string;
}

export async function searchText(
  filePath: string,
  pattern: string | RegExp,
  options: { maxResults?: number; skip?: number; caseSensitive?: boolean } = {}
): Promise<TextSearchResult> {
  const { maxResults = 100, caseSensitive = false } = options;
  let { skip = 0 } = options;
  let regex;
  if (typeof pattern === 'string') {
    let flags = 'gm';
    if (!caseSensitive)
      flags += 'i';
    regex = new RegExp(pattern, flags);
  } else
    regex = pattern;
  const fileHandle = await fs.open(filePath, 'r');
  try {
    const chunk = Buffer.alloc(65536); // 64 KB
    const decoder = new TextDecoder();
    const results: { line: number; col: number; text: string }[] = [];
    let end = true;
    let note;

    const readResult = await fileHandle.read(chunk, 0, chunk.length, 0);
    if (readResult.bytesRead === 0) // Empty file
      return { results, end };
    const bytes = chunk.subarray(0, readResult.bytesRead);
    const nullPos = bytes.indexOf(0);
    if (nullPos !== -1)
      note = `The file appears to be binary (NUL byte found at offset ${nullPos}); the text may be garbled.`;
    let lastText = decoder.decode(bytes);
    let offset = readResult.bytesRead;
    let lineCount = 1;
    let lastCol = 0;
    while (true) {
      const result = await fileHandle.read(chunk, 0, chunk.length, offset);
      const bytes = chunk.subarray(0, result.bytesRead);
      const text = decoder.decode(bytes);
      const fullText = lastText + text;
      const lastLinePos = Math.max(fullText.lastIndexOf('\n'), fullText.lastIndexOf('\r')) + 1;
      const textToSearch = lastLinePos && result.bytesRead ? fullText.slice(0, lastLinePos) : fullText;
      const tokens = textToSearch.split(/(\r\n|\r|\n)/);
      let index = 0;
      let lineStart = 0;
      let lineLength;
      if (tokens[index + 1])
        lineLength = tokens[index].length + tokens[index + 1].length;
      const matches = Array.from(textToSearch.matchAll(regex));
      for (const match of matches) {
        while (lineLength && lineStart + lineLength <= match.index) {
          lineStart += lineLength;
          lineCount++;
          lastCol = 0;
          index += 2;
          lineLength = tokens[index + 1] ? tokens[index].length + tokens[index + 1].length : undefined;
        }
        if (skip)
          skip--;
        else if (results.length < maxResults)
          results.push({ line: lineCount, col: lastCol + match.index - lineStart, text: match[0] });
        else if (results.length === maxResults) {
          end = false;
          break;
        }
      }
      if (matches.length) {
        const match = matches[matches.length - 1];
        const continuePos = match.index + match[0].length;
        while (lineLength && lineStart + lineLength <= continuePos) {
          lineStart += lineLength;
          lineCount++;
          index += 2;
          lineLength = tokens[index + 1] ? tokens[index].length + tokens[index + 1].length : undefined;
        }
        lastCol += continuePos - lineStart;
        lastText = fullText.slice(continuePos);
        if (match[0].endsWith('\r') && lastText.startsWith('\n'))
          lineCount--;
      } else {
        const lines = lastText.split(/\r\n|\r|\n/);
        lineCount += lines.length - 1;
        if (lastText.endsWith('\r') && text.startsWith('\n'))
          lineCount--;
        lastCol = 0;
        lastText = lines[lines.length - 1] + text;
      }

      if (result.bytesRead === 0) break; // End of file
      offset += result.bytesRead;
    }

    const result: TextSearchResult = { results, end };
    if (note)
      result.note = note;
    return result;
  } finally {
    fileHandle.close();
  }
}

export async function searchFilesWithValidation(
  rootPath: string,
  pattern: string,
  options: SearchOptions = {}
): Promise<string[]> {
  const { excludePatterns = [] } = options;
  const results: string[] = [];

  async function search(currentPath: string) {
    const entries = await fs.readdir(currentPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);

      try {
        const relativePath = path.relative(rootPath, fullPath);
        const shouldExclude = excludePatterns.some(excludePattern =>
          minimatch(relativePath, excludePattern, { dot: true })
        );

        if (shouldExclude) continue;

        // Use glob matching for the search pattern
        if (minimatch(relativePath, pattern, { dot: true })) {
          results.push(fullPath);
        }

        if (entry.isDirectory()) {
          await validatePath(fullPath, true);
          await search(fullPath);
        }
      } catch {
        continue;
      }
    }
  }

  await search(rootPath);
  return results;
}

export async function getFilesRecursive(dir: string): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });

  const files = await Promise.all(entries.map(async (entry) => {
    const fullPath = path.join(dir, entry.name);
    try {
      const validPath = await validatePath(fullPath, true);
      if (entry.isDirectory())
        return getFilesRecursive(validPath);
      return validPath;
    } catch {
      return [];
    }
  }));

  return files.flat();
}