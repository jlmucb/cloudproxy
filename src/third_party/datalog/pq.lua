--[[
% p q test from Chen & Warren
q(X) :- p(X).
q(a).
p(X) :- q(X).
q(X)?
]]

require "datalog"

-- Abbreviations that make the code more readable.

mv = datalog.make_var
mc = datalog.make_const
ml = datalog.make_literal
mr = datalog.make_clause

-- Ask with a simple printer for answers

function ask(literal)
   local ans = datalog.ask(literal)
   if ans then
      for i = 1,#ans do
	 io.write(ans.name)
	 if ans.arity > 0 then
	    io.write("(")
	    io.write(ans[i][1])
	    for j = 2,ans.arity do
	       io.write(", ")
	       io.write(ans[i][j])
	    end
	    io.write(").\n")
	 else
	    io.write(".\n")
	 end
      end
   end
   return ans
end

do
   -- Translation of q(X) :- p(X).
   local head = ml("q", {mv("X")})
   local body = {ml("p", {mv("X")})}
   datalog.assert(mr(head, body))
end

do
   -- Translation of q(a).
   local head = ml("q", {mc("a")})
   datalog.assert(mr(head, {}))
end

do
   -- Translation of p(X) :- q(X).
   local head = ml("p", {mv("X")})
   local body = {ml("q", {mv("X")})}
   datalog.assert(mr(head, body))
end

-- Translation of q(X)?
ask(ml("q", {mv("X")}))
