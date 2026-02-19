/**
 * @file comment.ts
 * @description A database interface for high-level language comments.
 *
 * Translated from Ghidra's comment.hh / comment.cc.
 */

import type { int4, uint4 } from '../core/types.js';
import { Address, MachExtreme } from '../core/address.js';
import {
  ElementId,
  Encoder,
  Decoder,
  ATTRIB_TYPE,
  ATTRIB_CONTENT,
  ATTRIB_SPACE,
} from '../core/marshal.js';
import { LowlevelError } from '../core/error.js';
import { SortedSet, SortedMap, type SortedSetIterator, type SortedMapIterator } from '../util/sorted-set.js';

// ---------------------------------------------------------------------------
// Forward-declared types not yet available
// ---------------------------------------------------------------------------

type FlowBlock = any;
type PcodeOp = any;
type Funcdata = any;
type BlockBasic = any;

// ---------------------------------------------------------------------------
// Marshaling element IDs specific to comment.cc
// ---------------------------------------------------------------------------

export const ELEM_COMMENT = new ElementId("comment", 86);
export const ELEM_COMMENTDB = new ElementId("commentdb", 87);
export const ELEM_TEXT = new ElementId("text", 88);

/** We need ELEM_ADDR for encoding addresses within comments. */
const ELEM_ADDR = new ElementId("addr", 11);

// ---------------------------------------------------------------------------
// Address decode helper
// ---------------------------------------------------------------------------

/**
 * Decode an Address from a stream decoder.
 *
 * This replicates the C++ Address::decode which reads an <addr> element
 * containing space and offset attributes.
 */
function decodeAddress(decoder: Decoder): Address {
  const elemId = decoder.openElement();
  let space: any = null;
  let offset = 0n;
  for (;;) {
    const attribId = decoder.getNextAttributeId();
    if (attribId === 0) break;
    if (attribId === ATTRIB_SPACE.getId()) {
      space = decoder.readSpace();
      decoder.rewindAttributes();
      const sizeRef = { val: 0 };
      offset = space.decodeAttributes_sized(decoder, sizeRef);
      break;
    }
  }
  decoder.closeElement(elemId);
  if (space === null) {
    return new Address();
  }
  return new Address(space, offset);
}

// ---------------------------------------------------------------------------
// Comment class
// ---------------------------------------------------------------------------

/**
 * A comment attached to a specific function and code address.
 *
 * Contains the actual character data of the comment. It is
 * fundamentally attached to a specific function and to the address of
 * an instruction (within the function's body). Comments
 * can be categorized as a header (or not) depending on whether
 * it should be displayed as part of the general description of the
 * function or not. Other properties can be assigned to a comment, to
 * allow the user to specify the subset of all comments they want to display.
 */
export class Comment {
  /** Possible properties associated with a comment */
  static readonly user1: uint4 = 1;
  static readonly user2: uint4 = 2;
  static readonly user3: uint4 = 4;
  static readonly header: uint4 = 8;
  static readonly warning: uint4 = 16;
  static readonly warningheader: uint4 = 32;

  /** The properties associated with the comment */
  private type: uint4;
  /** Sub-identifier for uniqueness */
  uniq: int4;
  /** Address of the function containing the comment */
  private funcaddr: Address;
  /** Address associated with the comment */
  private addr: Address;
  /** The body of the comment */
  private text: string;
  /** true if this comment has already been emitted */
  private emitted: boolean;

  /**
   * Constructor.
   * With no arguments creates a default comment for use with decode.
   */
  constructor();
  constructor(tp: uint4, fad: Address, ad: Address, uq: int4, txt: string);
  constructor(tp?: uint4, fad?: Address, ad?: Address, uq?: int4, txt?: string) {
    if (tp !== undefined) {
      this.type = tp;
      this.funcaddr = fad!;
      this.addr = ad!;
      this.uniq = uq!;
      this.text = txt!;
      this.emitted = false;
    } else {
      this.type = 0;
      this.funcaddr = new Address();
      this.addr = new Address();
      this.uniq = 0;
      this.text = '';
      this.emitted = false;
    }
  }

  /** Mark that this comment has been emitted */
  setEmitted(val: boolean): void {
    this.emitted = val;
  }

  /** Return true if this comment is already emitted */
  isEmitted(): boolean {
    return this.emitted;
  }

  /** Get the properties associated with the comment */
  getType(): uint4 {
    return this.type;
  }

  /** Get the address of the function containing the comment */
  getFuncAddr(): Address {
    return this.funcaddr;
  }

  /** Get the address to which the instruction is attached */
  getAddr(): Address {
    return this.addr;
  }

  /** Get the sub-sorting index */
  getUniq(): int4 {
    return this.uniq;
  }

  /** Get the body of the comment */
  getText(): string {
    return this.text;
  }

  /** Encode the comment to a stream */
  encode(encoder: Encoder): void {
    const tpname = Comment.decodeCommentType(this.type);
    encoder.openElement(ELEM_COMMENT);
    encoder.writeString(ATTRIB_TYPE, tpname);
    encoder.openElement(ELEM_ADDR);
    this.funcaddr.getSpace()!.encodeAttributes(encoder, this.funcaddr.getOffset());
    encoder.closeElement(ELEM_ADDR);
    encoder.openElement(ELEM_ADDR);
    this.addr.getSpace()!.encodeAttributes(encoder, this.addr.getOffset());
    encoder.closeElement(ELEM_ADDR);
    encoder.openElement(ELEM_TEXT);
    encoder.writeString(ATTRIB_CONTENT, this.text);
    encoder.closeElement(ELEM_TEXT);
    encoder.closeElement(ELEM_COMMENT);
  }

  /** Decode the comment from a stream */
  decode(decoder: Decoder): void {
    this.emitted = false;
    this.type = 0;
    const elemId = decoder.openElementId(ELEM_COMMENT);
    this.type = Comment.encodeCommentType(decoder.readStringById(ATTRIB_TYPE));
    this.funcaddr = decodeAddress(decoder);
    this.addr = decodeAddress(decoder);
    const subId = decoder.peekElement();
    if (subId !== 0) {
      decoder.openElement();
      this.text = decoder.readStringById(ATTRIB_CONTENT);
      decoder.closeElement(subId);
    }
    decoder.closeElement(elemId);
  }

  /** Convert name string to comment property */
  static encodeCommentType(name: string): uint4 {
    if (name === "user1") return Comment.user1;
    if (name === "user2") return Comment.user2;
    if (name === "user3") return Comment.user3;
    if (name === "header") return Comment.header;
    if (name === "warning") return Comment.warning;
    if (name === "warningheader") return Comment.warningheader;
    throw new LowlevelError("Unknown comment type: " + name);
  }

  /** Convert comment property to string */
  static decodeCommentType(val: uint4): string {
    switch (val) {
      case Comment.user1:
        return "user1";
      case Comment.user2:
        return "user2";
      case Comment.user3:
        return "user3";
      case Comment.header:
        return "header";
      case Comment.warning:
        return "warning";
      case Comment.warningheader:
        return "warningheader";
      default:
        break;
    }
    throw new LowlevelError("Unknown comment type");
  }
}

// ---------------------------------------------------------------------------
// CommentOrder comparator
// ---------------------------------------------------------------------------

/**
 * Compare two Comment objects.
 *
 * Comments are ordered first by function, then address,
 * then the sub-sort index.
 *
 * Returns negative if a < b, 0 if equal, positive if a > b.
 */
function commentOrderCompare(a: Comment, b: Comment): number {
  if (!a.getFuncAddr().equals(b.getFuncAddr())) {
    return a.getFuncAddr().lessThan(b.getFuncAddr()) ? -1 : 1;
  }
  if (!a.getAddr().equals(b.getAddr())) {
    return a.getAddr().lessThan(b.getAddr()) ? -1 : 1;
  }
  if (a.getUniq() !== b.getUniq()) {
    return a.getUniq() < b.getUniq() ? -1 : 1;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// CommentSet type
// ---------------------------------------------------------------------------

/** A set of comments sorted by function and address */
export type CommentSet = SortedSet<Comment>;
export type CommentSetIterator = SortedSetIterator<Comment>;

/** Create a new empty CommentSet */
function createCommentSet(): CommentSet {
  return new SortedSet<Comment>(commentOrderCompare);
}

// ---------------------------------------------------------------------------
// CommentDatabase (abstract interface)
// ---------------------------------------------------------------------------

/**
 * An interface to a container of comments.
 *
 * Comments can be added (and removed) from a database, keying
 * on the function and address the Comment is attached to.
 * The interface can generate a begin and end iterator covering
 * all Comment objects for a single function.
 */
export abstract class CommentDatabase {
  constructor() {}

  /** Clear all comments from this container */
  abstract clear(): void;

  /**
   * Clear all comments matching (one of) the indicated types.
   *
   * Clearing is restricted to comments belonging to a specific function and matching
   * at least one of the given properties.
   */
  abstract clearType(fad: Address, tp: uint4): void;

  /**
   * Add a new comment to the container.
   */
  abstract addComment(tp: uint4, fad: Address, ad: Address, txt: string): void;

  /**
   * Add a new comment to the container, making sure there is no duplicate.
   *
   * If there is already a comment at the same address with the same body, no
   * new comment is added.
   * @returns true if a new Comment was created, false if there was a duplicate
   */
  abstract addCommentNoDuplicate(tp: uint4, fad: Address, ad: Address, txt: string): boolean;

  /**
   * Remove the given Comment object from the container.
   */
  abstract deleteComment(com: Comment): void;

  /**
   * Get an iterator to the beginning of comments for a single function.
   */
  abstract beginComment(fad: Address): CommentSetIterator;

  /**
   * Get an iterator to the ending of comments for a single function.
   */
  abstract endComment(fad: Address): CommentSetIterator;

  /**
   * Encode all comments in the container to a stream.
   */
  abstract encode(encoder: Encoder): void;

  /**
   * Decode all comments from a <commentdb> element.
   */
  abstract decode(decoder: Decoder): void;
}

// ---------------------------------------------------------------------------
// CommentDatabaseInternal
// ---------------------------------------------------------------------------

/**
 * An in-memory implementation of the CommentDatabase API.
 *
 * All Comment objects are held in memory in a sorted container. This
 * can be used as stand-alone database of comments, or it can act as a
 * cache for some other container.
 */
export class CommentDatabaseInternal extends CommentDatabase {
  /** The sorted set of Comment objects */
  private commentset: CommentSet;

  constructor() {
    super();
    this.commentset = createCommentSet();
  }

  clear(): void {
    this.commentset.clear();
  }

  clearType(fad: Address, tp: uint4): void {
    const testcommbeg = new Comment(0, fad, new Address(MachExtreme.m_minimal), 0, "");
    const testcommend = new Comment(0, fad, new Address(MachExtreme.m_maximal), 65535, "");

    let iterbegin = this.commentset.lower_bound(testcommbeg);
    const iterend = this.commentset.lower_bound(testcommend);

    while (!iterbegin.equals(iterend)) {
      const iter = iterbegin.clone();
      iter.next();
      if ((iterbegin.value.getType() & tp) !== 0) {
        this.commentset.erase(iterbegin);
      }
      iterbegin = iter;
    }
  }

  addComment(tp: uint4, fad: Address, ad: Address, txt: string): void {
    const newcom = new Comment(tp, fad, ad, 65535, txt);
    // Find first element greater
    let iter = this.commentset.lower_bound(newcom);
    // turn into last element less than
    if (!iter.equals(this.commentset.begin())) {
      iter.prev();
    } else {
      // iter is at begin, there is no previous element
      // Set uniq to 0 and insert
      newcom.uniq = 0;
      this.commentset.insert(newcom);
      return;
    }
    newcom.uniq = 0;
    if (!iter.isEnd) {
      if (iter.value.getAddr().equals(ad) && iter.value.getFuncAddr().equals(fad)) {
        newcom.uniq = iter.value.getUniq() + 1;
      }
    }
    this.commentset.insert(newcom);
  }

  addCommentNoDuplicate(tp: uint4, fad: Address, ad: Address, txt: string): boolean {
    const newcom = new Comment(tp, fad, ad, 65535, txt);

    // Find first element greater
    let iter = this.commentset.lower_bound(newcom);
    newcom.uniq = 0; // Set the uniq AFTER the search
    while (!iter.equals(this.commentset.begin())) {
      iter.prev();
      if (iter.value.getAddr().equals(ad) && iter.value.getFuncAddr().equals(fad)) {
        if (iter.value.getText() === txt) {
          // Matching text, don't store it
          return false;
        }
        if (newcom.uniq === 0) {
          newcom.uniq = iter.value.getUniq() + 1;
        }
      } else {
        break;
      }
    }
    this.commentset.insert(newcom);
    return true;
  }

  deleteComment(com: Comment): void {
    this.commentset.eraseValue(com);
  }

  beginComment(fad: Address): CommentSetIterator {
    const testcomm = new Comment(0, fad, new Address(MachExtreme.m_minimal), 0, "");
    return this.commentset.lower_bound(testcomm);
  }

  endComment(fad: Address): CommentSetIterator {
    const testcomm = new Comment(0, fad, new Address(MachExtreme.m_maximal), 65535, "");
    return this.commentset.lower_bound(testcomm);
  }

  encode(encoder: Encoder): void {
    encoder.openElement(ELEM_COMMENTDB);
    const iter = this.commentset.begin();
    const end = this.commentset.end();
    while (!iter.equals(end)) {
      iter.value.encode(encoder);
      iter.next();
    }
    encoder.closeElement(ELEM_COMMENTDB);
  }

  decode(decoder: Decoder): void {
    const elemId = decoder.openElementId(ELEM_COMMENTDB);
    while (decoder.peekElement() !== 0) {
      const com = new Comment();
      com.decode(decoder);
      this.addComment(com.getType(), com.getFuncAddr(), com.getAddr(), com.getText());
    }
    decoder.closeElement(elemId);
  }
}

// ---------------------------------------------------------------------------
// Subsort -- internal sorting key for CommentSorter
// ---------------------------------------------------------------------------

/**
 * The sorting key for placing a Comment within a specific basic block.
 */
class Subsort {
  /** Either the basic block index or -1 for a function header */
  index: int4 = 0;
  /** The order index within the basic block */
  order: uint4 = 0;
  /** A final count to guarantee a unique sorting */
  pos: uint4 = 0;

  /** Compare comments based on basic block, then position within the block */
  lessThan(op2: Subsort): boolean {
    if (this.index === op2.index) {
      if (this.order === op2.order)
        return this.pos < op2.pos;
      return this.order < op2.order;
    }
    return this.index < op2.index;
  }

  /** Initialize a key for a header comment */
  setHeader(headerType: uint4): void {
    this.index = -1; // -1 indicates a header comment
    this.order = headerType;
  }

  /** Initialize a key for a basic block position */
  setBlock(i: int4, ord: uint4): void {
    this.index = i;
    this.order = ord;
  }

  /** Create a copy of this subsort */
  clone(): Subsort {
    const s = new Subsort();
    s.index = this.index;
    s.order = this.order;
    s.pos = this.pos;
    return s;
  }
}

/** Comparator for Subsort keys */
function subsortCompare(a: Subsort, b: Subsort): number {
  if (a.index !== b.index) return a.index < b.index ? -1 : 1;
  if (a.order !== b.order) return a.order < b.order ? -1 : 1;
  if (a.pos !== b.pos) return a.pos < b.pos ? -1 : 1;
  return 0;
}

// ---------------------------------------------------------------------------
// CommentSorter
// ---------------------------------------------------------------------------

/**
 * A class for sorting comments into and within basic blocks.
 *
 * The decompiler endeavors to display comments within the flow of the
 * source code statements it generates. Comments should be placed at or near
 * the statement that encompasses the address of the original instruction
 * to which the comment is attached. This is complicated by the fact that
 * instructions may get removed and transformed during decompilation and even whole
 * basic blocks may get removed.
 *
 * This class sorts comments into the basic block that contains
 * it. As statements are emitted, comments can get picked up, in the correct order,
 * even if there is no longer a specific p-code operation at the comment's address.
 * The decompiler maintains information about basic blocks that have been entirely
 * removed, in which case, the user can elect to not display the corresponding comments.
 *
 * This class also acts as state for walking comments within a specific basic block or
 * within the header.
 */
export class CommentSorter {
  static readonly header_basic: uint4 = 0;
  static readonly header_unplaced: uint4 = 1;

  /** Comments for the current function, sorted by block */
  private commmap: SortedMap<Subsort, Comment>;
  /** Iterator to current comment being walked */
  private start: SortedMapIterator<Subsort, Comment>;
  /** Last comment in current set being walked */
  private stop: SortedMapIterator<Subsort, Comment>;
  /** Statement landmark within current set of comments */
  private opstop: SortedMapIterator<Subsort, Comment>;
  /** True if unplaced comments should be displayed (in the header) */
  private displayUnplacedComments: boolean;

  constructor() {
    this.commmap = new SortedMap<Subsort, Comment>(subsortCompare);
    this.displayUnplacedComments = false;
    this.start = this.commmap.end();
    this.stop = this.commmap.end();
    this.opstop = this.commmap.end();
  }

  /**
   * Establish sorting key for a Comment.
   * Figure out position of given Comment and initialize its key.
   * @returns true if the Comment could be positioned at all
   */
  private findPosition(subsort: Subsort, comm: Comment, fd: Funcdata): boolean {
    if (comm.getType() === 0) return false;
    const fad: Address = fd.getAddress();
    if (((comm.getType() & (Comment.header | Comment.warningheader)) !== 0) && comm.getAddr().equals(fad)) {
      // If it is a header comment at the address associated with the beginning of the function
      subsort.setHeader(CommentSorter.header_basic);
      return true;
    }

    // Try to find block containing comment
    // Find op at lowest address greater or equal to comment's address
    let opiter: SortedMapIterator<any, any> = fd.beginOp(comm.getAddr());
    let backupOp: PcodeOp | null = null;
    if (!opiter.equals(fd.endOpAll()) && opiter.value !== undefined) { // If there is an op at or after the comment
      const op: PcodeOp = opiter.value;
      const block: BlockBasic = op.getParent();
      if (block === null) {
        throw new LowlevelError("Dead op reaching CommentSorter");
      }
      if (block.contains(comm.getAddr())) { // If the op's block contains the address
        // Associate comment with this op
        subsort.setBlock(block.getIndex(), op.getSeqNum().getOrder() as uint4);
        return true;
      }
      if (comm.getAddr().equals(op.getAddr())) {
        backupOp = op;
      }
    }
    if (!opiter.equals(fd.beginOpAll())) { // If there is a previous op
      opiter.prev();
      const op: PcodeOp = opiter.value;
      const block: BlockBasic = op.getParent();
      if (block === null) {
        throw new LowlevelError("Dead op reaching CommentSorter");
      }
      if (block.contains(comm.getAddr())) { // If the op's block contains the address
        // Treat the comment as being in this block at the very end
        subsort.setBlock(block.getIndex(), 0xffffffff);
        return true;
      }
    }
    if (backupOp !== null) {
      // Its possible the op migrated from its original basic block.
      // Since the address matches exactly, hang the comment on it
      subsort.setBlock(backupOp.getParent().getIndex(), backupOp.getSeqNum().getOrder() as uint4);
      return true;
    }
    if (fd.beginOpAll().equals(fd.endOpAll())) { // If there are no ops at all
      subsort.setBlock(0, 0); // Put comment at the beginning of the first block
      return true;
    }
    if (this.displayUnplacedComments) {
      subsort.setHeader(CommentSorter.header_unplaced);
      return true;
    }
    return false; // Basic block containing comment has been excised
  }

  /**
   * Collect and sort comments specific to the given function.
   *
   * Only keep comments matching one of a specific set of properties.
   * @param tp is the set of properties (may be zero)
   * @param fd is the given function
   * @param db is the container of comments to collect from
   * @param displayUnplaced is true if unplaced comments should be displayed in the header
   */
  setupFunctionList(tp: uint4, fd: Funcdata, db: CommentDatabase, displayUnplaced: boolean): void {
    this.commmap.clear();
    this.displayUnplacedComments = displayUnplaced;
    if (tp === 0) return;
    const fad: Address = fd.getAddress();
    const iter = db.beginComment(fad);
    const lastiter = db.endComment(fad);
    const subsort = new Subsort();

    subsort.pos = 0;

    while (!iter.equals(lastiter)) {
      const comm: Comment = iter.value;
      if (this.findPosition(subsort, comm, fd)) {
        comm.setEmitted(false);
        this.commmap.set(subsort.clone(), comm);
        subsort.pos += 1; // Advance the uniqueness counter
      }
      iter.next();
    }
  }

  /**
   * Prepare to walk comments from a single basic block.
   *
   * Find iterators that bound everything in the basic block.
   */
  setupBlockList(bl: FlowBlock): void {
    const subsortLo = new Subsort();
    subsortLo.index = bl.getIndex();
    subsortLo.order = 0;
    subsortLo.pos = 0;
    this.start = this.commmap.lower_bound(subsortLo);

    const subsortHi = new Subsort();
    subsortHi.index = bl.getIndex();
    subsortHi.order = 0xffffffff;
    subsortHi.pos = 0xffffffff;
    this.stop = this.commmap.upper_bound(subsortHi);
  }

  /**
   * Establish a p-code landmark within the current set of comments.
   *
   * This will generally get called with the root p-code op of a statement
   * being emitted by the decompiler. This establishes a key value within the
   * basic block, so it is known where to stop emitting comments within the
   * block for emitting the statement.
   */
  setupOpList(op: PcodeOp | null): void {
    if (op === null) {
      // If NULL op, pick up any remaining comments in this basic block
      this.opstop = this.stop.clone();
      return;
    }
    const subsort = new Subsort();
    subsort.index = op.getParent().getIndex();
    subsort.order = op.getSeqNum().getOrder() as uint4;
    subsort.pos = 0xffffffff;
    this.opstop = this.commmap.upper_bound(subsort);
  }

  /**
   * Prepare to walk comments in the header.
   *
   * Header comments are grouped together. Set up iterators.
   * @param headerType selects either header_basic or header_unplaced comments
   */
  setupHeader(headerType: uint4): void {
    const subsortLo = new Subsort();
    subsortLo.index = -1;
    subsortLo.order = headerType;
    subsortLo.pos = 0;
    this.start = this.commmap.lower_bound(subsortLo);

    const subsortHi = new Subsort();
    subsortHi.index = -1;
    subsortHi.order = headerType;
    subsortHi.pos = 0xffffffff;
    this.opstop = this.commmap.upper_bound(subsortHi);
  }

  /** Return true if there are more comments to emit in the current set */
  hasNext(): boolean {
    return !this.start.equals(this.opstop);
  }

  /** Advance to the next comment */
  getNext(): Comment {
    const res = this.start.value;
    this.start.next();
    return res;
  }
}
