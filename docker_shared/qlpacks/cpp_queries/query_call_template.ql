/**
 * @kind graph
 */

import cpp
import semmle.code.cpp.pointsto.CallGraph

from Function caller, FunctionCall callee, Function root
where
  root.hasName("ares__expand_name_validated")
  and allCalls(caller, callee.getTarget())
  and allCalls*(root, caller)
  and callee.getLocation().getFile() = root.getFile()
select caller, callee.getTarget()
