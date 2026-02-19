/**
 * @file capability.ts
 * @description Infrastructure for discovering code extensions to the decompiler.
 * Translated from capability.hh/cc
 */

/**
 * Class for automatically registering extension points to the decompiler.
 *
 * In C++, this uses static initializer feature. In TypeScript, extensions
 * must be explicitly registered via registerCapability() at startup.
 */
export abstract class CapabilityPoint {
  private static list: CapabilityPoint[] = [];

  protected constructor() {
    CapabilityPoint.list.push(this);
  }

  abstract initialize(): void;

  static initializeAll(): void {
    const list = CapabilityPoint.list;
    for (let i = 0; i < list.length; ++i) {
      list[i].initialize();
    }
    list.length = 0;
  }

  static getList(): CapabilityPoint[] {
    return CapabilityPoint.list;
  }
}
