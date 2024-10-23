import cpp
import semmle.code.cpp.ir.dataflow.DataFlow
import semmle.code.cpp.pointsto.CallGraph
// A configuration for finding function accesses flowing into function-pointer calls
class Conf extends DataFlow::Configuration {
  Conf() { this = "Conf" }

  override predicate isSource(DataFlow::Node source) { source.asExpr() instanceof FunctionAccess }

  override predicate isSink(DataFlow::Node sink) { sink.asExpr() = any(ExprCall call).getExpr() }
}

query predicate edges(Function a, Function b) {
  exists(FunctionAccess funcAccess, DataFlow::Node sink |
    // Flow from a function access to some sink (which is the expression of some `ExprCall`).
    any(Conf conf).hasFlow(DataFlow::exprNode(funcAccess), sink) and
    // And the call happens inside function `a`
    sink.getEnclosingCallable() = a and
    // And the function pointer is a pointer to function `b`
    b = funcAccess.getTarget()
  )
}

predicate hasPath(Function srcF, Function desF, string startName) {
  allCalls(srcF, desF) and  srcF.hasName(startName) 
}

predicate getCallGraph(Function start, Function end, string startName, string endName) {
  edges+(start, end) and
  start.hasName(startName) and
  end.hasName(endName)
}

// from Function start, Function end, Location start_loc, Location end_loc
// where  getCallGraph(start, end, "ares_evsys_kqueue_event_mod", end.getName()) or hasPath(start, end,"ares_evsys_kqueue_event_mod")
// and start_loc = start.getADeclarationEntry().getBlock().getLocation() and end_loc = end.getADeclarationEntry().getBlock().getLocation() 
// select start, end, start_loc.getFile(), end_loc.getFile(), start_loc.getStartLine() as start_body_start_line, start_loc.getEndLine() as start_body_end_line, end_loc.getStartLine() as end_body_start_line, end_loc.getEndLine() as end_body_end_line


from Function start, Function end, Location start_loc, Location end_loc
where   start.hasName("ares_evsys_kqueue_event_mod") and ( getCallGraph(start, end, "ares_evsys_kqueue_event_mod", end.getName())  or hasPath(start, end,"ares_evsys_kqueue_event_mod") ) and  start_loc = start.getADeclarationEntry().getBlock().getLocation() and end_loc = end.getLocation()
select start as caller, end as callee,  start.getFile() as caller_src, end.getFile() as callee_src, start_loc.getStartLine() as start_body_start_line, start_loc.getEndLine() as start_body_end_line, end_loc.getStartLine() as end_body_start_line, end_loc.getEndLine() as end_body_end_line, start.getFullSignature() as caller_signature, start.getParameterString() as caller_parameter_string, start.getType() as caller_return_type, start.getUnspecifiedType() as caller_return_type_inferred, end.getFullSignature() as callee_signature, end.getParameterString() as callee_parameter_string, end.getType() as callee_return_type, end.getUnspecifiedType() as callee_return_type_inferred
// , start_loc.getFile(), end_loc.getFile(), start_loc.getStartLine() as start_body_start_line, start_loc.getEndLine() as start_body_end_line, end_loc.getStartLine() as end_body_start_line, end_loc.getEndLine() as end_body_end_line