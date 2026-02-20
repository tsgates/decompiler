// test/debug-longdouble5.ts - test float format for size 10
import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FloatFormat } from '../src/core/float.js';

startDecompilerLibrary('/opt/ghidra');

// Test FloatFormat for size 10 (80-bit x87 extended precision)
console.log("=== FloatFormat Size 10 Test ===");
const ff10 = new FloatFormat(10);
console.log("Size:", ff10.getSize());

// For 80-bit extended precision (x87):
// signbit_pos = 79
// exp_pos = 64
// exp_size = 15
// frac_pos = 0
// frac_size = 63  (note: j-bit is explicit, not implied)
// bias = 16383
// jbitimplied = false

// The constant 27.632 in x87 format
// Let's check what the encoding would be for a known value
// 0x3f_e666_6666_6666_6666  is 0.7 in long double (from the test data at 0x1012b0)
const encodingBytes = BigInt("0x666666666666e63f");  // little-endian bytes from the binary
// The data at 0x1012B0 is: 66 66 66 66 66 66 e6 3f (8 bytes, but float10 is 10 bytes)
// Actually wait, that's only 8 bytes for what should be a 10-byte float
// Let me recheck the test data...

// From longdouble.xml bytechunk at 0x1012b0:
// 666666666666e63f  -- that's 8 bytes
// But float10 needs 10 bytes...

console.log("\n=== FloatFormat defaults for size 10 ===");
console.log("(Note: constructor only has cases for size 4 and 8)");
console.log("This means for size 10, all encoding parameters are left at 0!");

// Let's verify - the 4-byte and 8-byte formats
const ff4 = new FloatFormat(4);
const ff8 = new FloatFormat(8);

console.log("\n4-byte float format: extractExponentCode from 0x40DC28F6 =", ff4.extractExponentCode(0x40DC28F6n));
const { value: val4 } = ff4.getHostFloat(0x40DC28F6n);
console.log("4-byte value:", val4);  // Should be ~6.88...

console.log("\n8-byte float format: extractExponentCode from a known value");

// Now test what happens with a 10-byte format (should be broken since constructor doesn't handle sz==10)
try {
  const result = ff10.extractExponentCode(0x4003DCA1C0831269n);
  console.log("10-byte extractExponentCode:", result);
} catch (e: any) {
  console.log("10-byte extractExponentCode error:", e.message);
}
