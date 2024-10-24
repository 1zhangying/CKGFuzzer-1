import cpp

// Direct function calls
predicate directCall(Function caller, Function callee) {
  exists(FunctionCall fc |
    fc.getEnclosingFunction() = caller and
    fc.getTarget() = callee
  )
}

// Combined edge predicate
predicate edges(Function caller, Function callee) {
  directCall(caller, callee)
}

// Reachability predicate (includes transitive calls)
predicate reachable(Function src, Function dest) {
  edges(src, dest)
  or
  exists(Function mid |
    edges(src, mid) and
    reachable(mid, dest)
  )
}

// Entry point predicate
predicate isEntryPoint(Function f) {
  f.hasName("ENTRY_FNC") or
  f.hasName("main")
}

// Main query
from Function start, Function end, Location start_loc, Location end_loc
where
  isEntryPoint(start) and
  reachable(start, end) and
  start_loc = start.getLocation() and
  end_loc = end.getLocation()
select
  start as caller,
  end as callee,
  start.getFile().getRelativePath() as caller_src,
  end.getFile().getRelativePath() as callee_src,
  start_loc.getStartLine() as start_body_start_line,
  start_loc.getEndLine() as start_body_end_line,
  end_loc.getStartLine() as end_body_start_line,
  end_loc.getEndLine() as end_body_end_line,
  start.getName() as caller_signature,
  start.getNumberOfParameters() as caller_parameter_count,
  start.getType().toString() as caller_return_type,
  end.getName() as callee_signature,
  end.getNumberOfParameters() as callee_parameter_count,
  end.getType().toString() as callee_return_type