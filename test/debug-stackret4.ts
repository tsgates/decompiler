import '../src/console/xml_arch.js';
import { startDecompilerLibrary } from '../src/console/libdecomp.js';
import { FunctionTestCollection } from '../src/console/testfunction.js';
import { StringWriter } from '../src/util/writer.js';
import { OpCode } from '../src/core/opcodes.js';

startDecompilerLibrary('/opt/ghidra');

// Monkey-patch RuleHumptyDumpty to trace
// Import the module to get the class
const coreaction = await import('../src/decompiler/coreaction.js');

// Find and patch RuleHumptyDumpty via the constructor chain
const { Rule } = await import('../src/decompiler/action.js');

// Direct approach: patch the rule's applyOp in the action pool
// We need to get at the rule instance after it's registered. Let's just add traces to the class.

// Access RuleHumptyDumpty - it's not exported, but we can access it through the prototype chain
// Instead, let's just add a trace wrapper in the apply function

// Simpler: add env var trace in RuleHumptyDumpty
// Actually we already implemented it. Let's trace by temporarily adding console.log in the code
// Instead, let's use a different approach: run the test and check if RuleHumptyDumpty gets registered properly

// Check if RuleHumptyDumpty has getOpList
const { ActionPool } = await import('../src/decompiler/action.js');
const origAddRule = ActionPool.prototype.addRule;
ActionPool.prototype.addRule = function(rule: any) {
  if (rule.constructor.name === 'RuleHumptyDumpty' || rule.constructor.name === 'RuleDumptyHump') {
    const opList = rule.getOpList ? rule.getOpList() : [];
    console.log(`[addRule] ${rule.constructor.name} opList=${JSON.stringify(opList)}`);
  }
  return origAddRule.call(this, rule);
};

(globalThis as any).__DUMP_OUTPUT__ = true;

const writer = new StringWriter();
const tc = new FunctionTestCollection(writer);
tc.loadTest('ghidra-src/Ghidra/Features/Decompiler/src/decompile/datatests/stackreturn.xml');
const failures: string[] = [];
tc.runTests(failures);
console.log(writer.toString());
if (failures.length > 0) {
  console.log('Failures:', failures);
}
