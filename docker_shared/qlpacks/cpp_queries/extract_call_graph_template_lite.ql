import cpp

// Direct function calls
predicate directCall(Function caller, Function callee) {
  exists(FunctionCall fc |
    fc.getEnclosingFunction() = caller and
    fc.getTarget() = callee
  )
}

// Virtual method calls
predicate virtualCall(Function caller, Function callee) {
  exists(Call vc |
    vc.getEnclosingFunction() = caller and
    vc.getTarget() = callee and
    exists(MemberFunction mf |  
      mf = callee and
      exists(MemberFunction base |
        base = mf.getAnOverriddenFunction*() and
        base.isVirtual()
      )
    )
  )
}

// Combined edge predicate (LITE: no function pointer / DataFlow analysis)
predicate edges(Function caller, Function callee) {
  directCall(caller, callee) or
  virtualCall(caller, callee)
}

// Reachability predicate - LITE version (direct calls only, no transitive closure)
predicate reachable(Function src, Function dest) {
  edges(src, dest)
}

// Entry point predicate
predicate isEntryPoint(Function f) {
  f.hasName("ENTRY_FNC")
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
  start.getFile() as caller_src,
  end.getFile() as callee_src,
  start_loc.getStartLine() as start_body_start_line,
  start_loc.getEndLine() as start_body_end_line,
  end_loc.getStartLine() as end_body_start_line,
  end_loc.getEndLine() as end_body_end_line,
  start.getFullSignature() as caller_signature,
  start.getParameterString() as caller_parameter_string,
  start.getType() as caller_return_type,
  start.getUnspecifiedType() as caller_return_type_inferred,
  end.getFullSignature() as callee_signature,
  end.getParameterString() as callee_parameter_string,
  end.getType() as callee_return_type,
  end.getUnspecifiedType() as callee_return_type_inferred