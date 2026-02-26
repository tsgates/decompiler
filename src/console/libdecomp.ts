/**
 * @file libdecomp.ts
 * @description Library initialization routines for the decompiler.
 *
 * Translated from Ghidra's libdecomp.hh / libdecomp.cc
 */

import { AttributeId, ElementId } from '../core/marshal.js';
import { CapabilityPoint } from '../core/capability.js';
import { ArchitectureCapability } from '../decompiler/architecture.js';
import { SleighArchitecture, specpaths } from '../console/sleigh_arch.js';

/**
 * Initialize the decompiler library.
 *
 * In C++ there are three overloads; here we combine them into a single function
 * with optional parameters.
 *
 * @param sleighhome - optional root path for scanning sleigh directories; when omitted, bundled spec files are used
 * @param extrapaths - optional array of additional specification paths
 */
export function startDecompilerLibrary(
  sleighhome?: string | null,
  extrapaths?: string[]
): void {
  AttributeId.initialize();
  ElementId.initialize();
  CapabilityPoint.initializeAll();
  ArchitectureCapability.sortCapabilities();

  if (sleighhome != null) {
    SleighArchitecture.scanForSleighDirectories(sleighhome);
  } else {
    SleighArchitecture.scanForBundledSpecs();
  }

  if (extrapaths !== undefined) {
    for (let i = 0; i < extrapaths.length; ++i) {
      specpaths.addDir2Path(extrapaths[i]);
    }
  }
}

/**
 * Shutdown the decompiler library (currently a no-op, matching C++ implementation).
 */
export function shutdownDecompilerLibrary(): void {
  // Empty -- matches C++ implementation
}
