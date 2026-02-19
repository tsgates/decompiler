/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file paramid.ts
 * @description Parameter identification analysis, translated from paramid.hh / paramid.cc
 */

import { Address } from "../core/address.js";
import {
  Encoder,
  ElementId,
  ATTRIB_VAL,
  ATTRIB_NAME,
  ATTRIB_MODEL,
  ATTRIB_EXTRAPOP,
  ELEM_INPUT,
  ELEM_OUTPUT,
} from "../core/marshal.js";
import { OpCode } from "../core/opcodes.js";
import { VarnodeData } from "../core/pcoderaw.js";
import { AddrSpace } from "../core/space.js";
import { Varnode } from "./varnode.js";
import { ELEM_ADDR } from "./varnode.js";
import { PcodeOp } from "./op.js";
import { Datatype } from "./type.js";
import { FuncProto, ProtoParameter, ProtoModel } from "./fspec.js";

// Forward type declarations for types from not-yet-written modules
type Funcdata = any;

// ---------------------------------------------------------------------------
// Marshaling element IDs
// ---------------------------------------------------------------------------

/** Marshaling element \<parammeasures> */
export const ELEM_PARAMMEASURES = new ElementId("parammeasures", 106);
/** Marshaling element \<proto> */
export const ELEM_PROTO = new ElementId("proto", 107);
/** Marshaling element \<rank> */
export const ELEM_RANK = new ElementId("rank", 108);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAXDEPTH = 10;

// ---------------------------------------------------------------------------
// ParamMeasure
// ---------------------------------------------------------------------------

/** Specifies whether a parameter is input or output */
export const enum ParamIDIO {
  INPUT = 0,
  OUTPUT = 1,
}

/** Ranking of how directly a parameter location is used */
export const enum ParamRank {
  BESTRANK = 1,
  DIRECTWRITEWITHOUTREAD = 1, // Output
  DIRECTREAD = 2,             // Input. Must be same as DIRECTWRITEWITHREAD so that
                              // walkforward as part of walkbackward works
                              // for detecting (not that DIRECTREAD is lower rank that DIRECTWRITEWITHOUTREAD)
  DIRECTWRITEWITHREAD = 2,   // Output
  DIRECTWRITEUNKNOWNREAD = 3, // Output
  SUBFNPARAM = 4,            // Input
  THISFNPARAM = 4,           // Output
  SUBFNRETURN = 5,           // Output
  THISFNRETURN = 5,          // Input
  INDIRECT = 6,              // Input or Output
  WORSTRANK = 7,
}

/** Internal walk state for parameter rank analysis */
export interface WalkState {
  best: boolean;
  depth: number;
  terminalrank: ParamRank;
}

/**
 * A measure of how directly a parameter location is used.
 *
 * Given a Varnode that is a parameter to a function (input or output),
 * this class analyzes how directly the Varnode is read or written,
 * assigning a rank that indicates confidence in the parameter identification.
 */
export class ParamMeasure {
  private vndata: VarnodeData;
  private vntype: Datatype | null;
  private rank: ParamRank;
  private io: ParamIDIO;
  private numcalls: number;

  constructor(addr: Address, sz: number, dt: Datatype | null, io_in: ParamIDIO) {
    this.vndata = new VarnodeData(addr.getSpace(), addr.getOffset(), sz);
    this.vntype = dt;
    this.io = io_in;
    this.rank = ParamRank.WORSTRANK;
    this.numcalls = 0;
  }

  private updaterank(rank_in: ParamRank, best: boolean): void {
    this.rank = best ? Math.min(this.rank, rank_in) : Math.max(this.rank, rank_in);
  }

  // NOTES FROM 20121206 W/Decompiler-Man
  // direct reads is for all opcodes, with special for these:
  // BRANCH is direct read on input0.  No direct write.
  // CBRANCH is direct read on input0 and input1.  No direct write.
  // BRANCHIND is direct read on input0 (like call but no params).  No direct write.
  // CALL is direct read on input0 (putative/presumptive param flag on params--other inputs).
  //   Special (non-direct) write of output.
  // CALLIND same as on CALL.  Special (non-direct) write of output.
  // CALLOTHER is direct read on ALL PARAMETERS (input0 and up)--is specified in sleigh.
  //   Direct write if output exists.
  // INDIRECT is least powerful input and output of all.
  // MULTIEQUALS is flow through but must test for and not flow through loop paths
  //   (whether from param forward our return backward directions).

  private walkforward(state: WalkState, ignoreop: PcodeOp | null, vn: Varnode): void {
    state.depth += 1;
    if (state.depth >= MAXDEPTH) {
      state.depth -= 1;
      return;
    }
    let idx = vn.beginDescend();
    const end = vn.endDescend();
    while (this.rank !== state.terminalrank && idx !== end) {
      const op: PcodeOp = vn.getDescend(idx);
      if (op !== ignoreop) {
        const oc: OpCode = op.code();
        switch (oc) {
          case OpCode.CPUI_BRANCH:
          case OpCode.CPUI_BRANCHIND:
            if (op.getSlot(vn) === 0) this.updaterank(ParamRank.DIRECTREAD, state.best);
            break;
          case OpCode.CPUI_CBRANCH:
            if (op.getSlot(vn) < 2) this.updaterank(ParamRank.DIRECTREAD, state.best);
            break;
          case OpCode.CPUI_CALL:
          case OpCode.CPUI_CALLIND:
            if (op.getSlot(vn) === 0) {
              this.updaterank(ParamRank.DIRECTREAD, state.best);
            } else {
              this.numcalls++;
              this.updaterank(ParamRank.SUBFNPARAM, state.best);
            }
            break;
          case OpCode.CPUI_CALLOTHER:
            this.updaterank(ParamRank.DIRECTREAD, state.best);
            break;
          case OpCode.CPUI_RETURN:
            this.updaterank(ParamRank.THISFNRETURN, state.best);
            break;
          case OpCode.CPUI_INDIRECT:
            this.updaterank(ParamRank.INDIRECT, state.best);
            break;
          case OpCode.CPUI_MULTIEQUAL:
            // The only op for which there can be a loop in the graph is with the MULTIEQUAL
            // (not for CALL, etc.).
            // Walk forward only if the path is not part of a loop.
            if (!op.getParent()!.isLoopIn(op.getSlot(vn))) {
              this.walkforward(state, null, op.getOut()!);
            }
            break;
          default:
            this.updaterank(ParamRank.DIRECTREAD, state.best);
            break;
        }
      }
      idx++;
    }
    state.depth -= 1;
  }

  private walkbackward(state: WalkState, ignoreop: PcodeOp | null, vn: Varnode): void {
    if (vn.isInput()) {
      this.updaterank(ParamRank.THISFNPARAM, state.best);
      return;
    } else if (!vn.isWritten()) {
      this.updaterank(ParamRank.THISFNPARAM, state.best); // TODO: not sure about this.
      return;
    }

    const op: PcodeOp = vn.getDef()!;
    const oc: OpCode = op.code();
    switch (oc) {
      case OpCode.CPUI_BRANCH:
      case OpCode.CPUI_BRANCHIND:
      case OpCode.CPUI_CBRANCH:
      case OpCode.CPUI_CALL:
      case OpCode.CPUI_CALLIND:
        break;
      case OpCode.CPUI_CALLOTHER:
        if (op.getOut() !== null) this.updaterank(ParamRank.DIRECTREAD, state.best);
        break;
      case OpCode.CPUI_RETURN:
        this.updaterank(ParamRank.SUBFNRETURN, state.best);
        break;
      case OpCode.CPUI_INDIRECT:
        this.updaterank(ParamRank.INDIRECT, state.best);
        break;
      case OpCode.CPUI_MULTIEQUAL:
        // The only op for which there can be a loop in the graph is with the MULTIEQUAL
        // (not for CALL, etc.).
        // Walk backward only if the path is not part of a loop.
        for (let slot = 0; slot < op.numInput() && this.rank !== state.terminalrank; slot++) {
          if (!op.getParent()!.isLoopIn(slot)) {
            this.walkbackward(state, op, op.getIn(slot)!);
          }
        }
        break;
      default:
        // Might be DIRECTWRITEWITHOUTREAD, but we do not know yet.
        // So now try to walk forward to see if there is at least one path
        // forward (other than the path we took to get here walking backward)
        // in which there is not a direct read of this write.
        {
          const pmfw = new ParamMeasure(
            vn.getAddr(), vn.getSize(), vn.getType(), ParamIDIO.INPUT
          );
          pmfw.calculateRank(false, vn, ignoreop);
          if (pmfw.getMeasure() === ParamRank.DIRECTREAD) {
            this.updaterank(ParamRank.DIRECTWRITEWITHREAD, state.best);
          } else {
            this.updaterank(ParamRank.DIRECTWRITEWITHOUTREAD, state.best);
          }
        }
        break;
    }
  }

  /**
   * Calculate the rank of this parameter measure.
   * @param best - true to find the best (minimum) rank, false for worst (maximum)
   * @param basevn - the base Varnode to start the walk from
   * @param ignoreop - a PcodeOp to ignore during the walk (or null)
   */
  calculateRank(best: boolean, basevn: Varnode, ignoreop: PcodeOp | null): void {
    const state: WalkState = {
      best: best,
      depth: 0,
      terminalrank: ParamRank.WORSTRANK,
    };
    if (best) {
      this.rank = ParamRank.WORSTRANK;
      state.terminalrank = (this.io === ParamIDIO.INPUT)
        ? ParamRank.DIRECTREAD
        : ParamRank.DIRECTWRITEWITHOUTREAD;
    } else {
      this.rank = ParamRank.BESTRANK;
      state.terminalrank = ParamRank.INDIRECT;
    }
    this.numcalls = 0;
    if (this.io === ParamIDIO.INPUT) {
      this.walkforward(state, ignoreop, basevn);
    } else {
      this.walkbackward(state, ignoreop, basevn);
    }
  }

  /**
   * Encode this parameter measure to an Encoder.
   * @param encoder - the stream encoder
   * @param tag - the ElementId tag to wrap the output in
   * @param moredetail - true to include rank detail
   */
  encode(encoder: Encoder, tag: ElementId, moredetail: boolean): void {
    encoder.openElement(tag);
    encoder.openElement(ELEM_ADDR);
    (this.vndata.space as AddrSpace).encodeAttributes(encoder, this.vndata.offset, this.vndata.size);
    encoder.closeElement(ELEM_ADDR);
    this.vntype!.encodeRef(encoder);
    if (moredetail) {
      encoder.openElement(ELEM_RANK);
      encoder.writeSignedInteger(ATTRIB_VAL, this.rank);
      encoder.closeElement(ELEM_RANK);
    }
    encoder.closeElement(tag);
  }

  /**
   * Write a human-readable description to a stream.
   * @param s - the output stream
   * @param moredetail - true to include additional detail
   */
  savePretty(s: { write(s: string): void }, moredetail: boolean): void {
    s.write("  Space: " + this.vndata.space!.getName() + "\n");
    s.write("  Addr: " + this.vndata.offset + "\n");
    s.write("  Size: " + this.vndata.size + "\n");
    s.write("  Rank: " + this.rank + "\n");
  }

  /**
   * Get the rank as a numeric measure.
   * @returns the rank value as a number
   */
  getMeasure(): number {
    return this.rank as number;
  }
}

// ---------------------------------------------------------------------------
// ParamIDAnalysis
// ---------------------------------------------------------------------------

/**
 * Performs parameter identification analysis on a function.
 *
 * Constructs lists of input and output parameter measures for a given
 * Funcdata, then can encode or pretty-print the results.
 */
export class ParamIDAnalysis {
  private fd: Funcdata;
  private InputParamMeasures: ParamMeasure[];
  private OutputParamMeasures: ParamMeasure[];

  /**
   * Construct a parameter ID analysis.
   * @param fd_in - the Funcdata to analyze
   * @param justproto - if true, only provide info on the recovered prototype
   */
  constructor(fd_in: Funcdata, justproto: boolean) {
    this.fd = fd_in;
    this.InputParamMeasures = [];
    this.OutputParamMeasures = [];

    if (justproto) {
      // We only provide info on the recovered prototype
      const fproto: FuncProto = this.fd.getFuncProto();
      const num: number = fproto.numParams();
      for (let i = 0; i < num; ++i) {
        const param: ProtoParameter = fproto.getParam(i)!;
        this.InputParamMeasures.push(
          new ParamMeasure(param.getAddress(), param.getSize(), param.getType(), ParamIDIO.INPUT)
        );
        const vn: Varnode | null = this.fd.findVarnodeInput(param.getSize(), param.getAddress());
        if (vn !== null) {
          this.InputParamMeasures[this.InputParamMeasures.length - 1].calculateRank(true, vn, null);
        }
      }

      const outparam: ProtoParameter = fproto.getOutput()!;
      if (!outparam.getAddress().isInvalid()) {
        // If we don't have a void type
        this.OutputParamMeasures.push(
          new ParamMeasure(
            outparam.getAddress(), outparam.getSize(), outparam.getType(), ParamIDIO.OUTPUT
          )
        );
        const rtnOps: PcodeOp[] = this.fd.getOpsOfOpcode(OpCode.CPUI_RETURN) ?? [];
        for (let rtnIdx = 0; rtnIdx < rtnOps.length; rtnIdx++) {
          const rtn_op: PcodeOp = rtnOps[rtnIdx];
          // For RETURN op, input0 is address location of indirect return, input1,
          // if it exists, is the Varnode returned, output = not sure.
          if (rtn_op.numInput() === 2) {
            const ovn: Varnode | null = rtn_op.getIn(1);
            if (ovn !== null) {
              // Not a void return
              this.OutputParamMeasures[this.OutputParamMeasures.length - 1]
                .calculateRank(true, ovn, rtn_op);
              break;
            }
          }
        }
      }
    } else {
      // Need to list input varnodes that are outside of the model
      const iter = this.fd.beginDefFlags(Varnode.input);
      const enditer = this.fd.endDefFlags(Varnode.input);
      let current = iter;
      while (!current.equals(enditer)) {
        const invn: Varnode = current.get();
        current = current.next();
        this.InputParamMeasures.push(
          new ParamMeasure(invn.getAddr(), invn.getSize(), invn.getType(), ParamIDIO.INPUT)
        );
        this.InputParamMeasures[this.InputParamMeasures.length - 1]
          .calculateRank(true, invn, null);
      }
    }
  }

  /**
   * Encode the analysis results to an Encoder.
   * @param encoder - the stream encoder
   * @param moredetail - true to include rank detail
   */
  encode(encoder: Encoder, moredetail: boolean): void {
    encoder.openElement(ELEM_PARAMMEASURES);
    encoder.writeString(ATTRIB_NAME, this.fd.getName());
    this.fd.getAddress().encode(encoder);
    encoder.openElement(ELEM_PROTO);

    encoder.writeString(ATTRIB_MODEL, this.fd.getFuncProto().getModelName());
    const extrapop: number = this.fd.getFuncProto().getExtraPop();
    if (extrapop === ProtoModel.extrapop_unknown) {
      encoder.writeString(ATTRIB_EXTRAPOP, "unknown");
    } else {
      encoder.writeSignedInteger(ATTRIB_EXTRAPOP, extrapop);
    }
    encoder.closeElement(ELEM_PROTO);

    for (const pm of this.InputParamMeasures) {
      pm.encode(encoder, ELEM_INPUT, moredetail);
    }
    for (const pm of this.OutputParamMeasures) {
      pm.encode(encoder, ELEM_OUTPUT, moredetail);
    }
    encoder.closeElement(ELEM_PARAMMEASURES);
  }

  /**
   * Write a human-readable description to a stream.
   * @param s - the output stream
   * @param moredetail - true to include additional detail
   */
  savePretty(s: { write(s: string): void }, moredetail: boolean): void {
    s.write("Param Measures\nFunction: " + this.fd.getName() +
      "\nAddress: 0x" + this.fd.getAddress().getOffset().toString(16) + "\n");
    s.write("Model: " + this.fd.getFuncProto().getModelName() +
      "\nExtrapop: " + this.fd.getFuncProto().getExtraPop() + "\n");
    s.write("Num Params: " + this.InputParamMeasures.length + "\n");
    for (const pm of this.InputParamMeasures) {
      pm.savePretty(s, moredetail);
    }
    s.write("Num Returns: " + this.OutputParamMeasures.length + "\n");
    for (const pm of this.OutputParamMeasures) {
      pm.savePretty(s, moredetail);
    }
    s.write("\n");
  }
}
