/**
 * @file filemanage.ts
 * @description File path utilities, translated from filemanage.hh/cc
 */

import * as fs from 'fs';
import * as path from 'path';

/**
 * File management class for searching files and managing paths.
 */
export class FileManage {
  private pathlist: string[] = [];

  static readonly separator = path.sep;

  /** Add a directory to the search path */
  addDir2Path(dir: string): void {
    this.pathlist.push(dir);
  }

  /** Add current working directory to the search path */
  addCurrentDir(): void {
    this.pathlist.push(process.cwd());
  }

  /** Return the number of directories in the search path */
  getPathCount(): number {
    return this.pathlist.length;
  }

  /**
   * Resolve a full pathname by searching the path list.
   * Returns the resolved path or empty string if not found.
   */
  findFile(name: string): string {
    // If absolute path, just check existence
    if (path.isAbsolute(name)) {
      if (fs.existsSync(name)) return name;
      return '';
    }

    for (const dir of this.pathlist) {
      const full = path.join(dir, name);
      if (fs.existsSync(full)) return full;
    }

    return '';
  }

  /**
   * Get list of files matching a pattern (suffix or prefix).
   * @param match - the pattern to match
   * @param isSuffix - true to match suffix, false to match prefix
   */
  matchList(match: string, isSuffix: boolean): string[] {
    const res: string[] = [];
    for (const dir of this.pathlist) {
      FileManage.matchListDir(res, match, isSuffix, dir, false);
    }
    return res;
  }

  /** Check if character is a path separator */
  static isSeparator(c: string): boolean {
    return c === '/' || c === '\\';
  }

  /** Check if the given path is a directory */
  static isDirectory(p: string): boolean {
    try {
      return fs.statSync(p).isDirectory();
    } catch {
      return false;
    }
  }

  /** Check if a path is absolute */
  static isAbsolutePath(full: string): boolean {
    return path.isAbsolute(full);
  }

  /**
   * List files in a directory matching a pattern.
   */
  static matchListDir(
    res: string[],
    match: string,
    isSuffix: boolean,
    dir: string,
    allowdot: boolean
  ): void {
    try {
      const entries = fs.readdirSync(dir);
      for (const entry of entries) {
        if (!allowdot && entry.startsWith('.')) continue;
        if (isSuffix) {
          if (entry.endsWith(match)) {
            res.push(path.join(dir, entry));
          }
        } else {
          if (entry.startsWith(match)) {
            res.push(path.join(dir, entry));
          }
        }
      }
    } catch {
      // Directory doesn't exist or can't be read
    }
  }

  /** List all files/directories in the given directory */
  static directoryList(dirname: string, allowdot = false): string[] {
    const res: string[] = [];
    try {
      const entries = fs.readdirSync(dirname);
      for (const entry of entries) {
        if (!allowdot && entry.startsWith('.')) continue;
        res.push(path.join(dirname, entry));
      }
    } catch {
      // Directory doesn't exist
    }
    return res;
  }

  /** Recursively scan directory for files matching a name */
  static scanDirectoryRecursive(
    res: string[],
    matchname: string,
    rootpath: string,
    maxdepth: number
  ): void {
    if (maxdepth <= 0) return;
    try {
      const entries = fs.readdirSync(rootpath, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name.startsWith('.')) continue;
        const full = path.join(rootpath, entry.name);
        if (entry.isDirectory()) {
          FileManage.scanDirectoryRecursive(res, matchname, full, maxdepth - 1);
        } else if (entry.name === matchname) {
          res.push(full);
        }
      }
    } catch {
      // Can't read directory
    }
  }

  /** Split a full path into directory and base name */
  static splitPath(full: string): { path: string; base: string } {
    return {
      path: path.dirname(full),
      base: path.basename(full),
    };
  }

  /**
   * Discover the Ghidra root directory given argv[0].
   * Walks up from the executable location looking for the Ghidra directory structure.
   */
  static discoverGhidraRoot(argv0: string): string {
    const resolved = path.resolve(argv0);
    const parts = resolved.split(path.sep);

    // Walk up looking for a Ghidra installation
    for (let level = parts.length - 1; level >= 0; level--) {
      const candidate = parts.slice(0, level + 1).join(path.sep);
      const processorDir = path.join(candidate, 'Ghidra', 'Processors');
      if (fs.existsSync(processorDir)) {
        return candidate;
      }
    }

    return '';
  }
}
