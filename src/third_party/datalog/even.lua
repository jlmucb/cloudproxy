require "datalog"

-- This file shows how to use the datalog module with Lua.  The
-- example demonstrates a rather inefficient way of determining if a
-- number is odd.

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

-- RULES

-- The even and odd rules are:
--
-- even(N) :- N = 0.
-- even(N) :- succ(N, M), odd(M).
-- odd(N) :- succ(N, M), even(M).

-- Translation of:
-- even(N) :- N = 0.

function even_base_case()
   local head = ml("even", {mv("N")})
   local body = {ml("=", {mv("N"), mc(0)})}
   return datalog.assert(mr(head, body))
end

-- Translation of:
-- even(N) :- succ(N, M), odd(M).

function even_inductive_case()
   local head = ml("even", {mv("N")})
   local body = {ml("succ", {mv("N"), mv("M")}),
		 ml("odd", {mv("M")})}
   return datalog.assert(mr(head, body))
end

-- Translation of:
-- odd(N) :- succ(N, M), even(M).

function odd_inductive_case()
   local head = ml("odd", {mv("N")})
   local body = {ml("succ", {mv("N"), mv("M")}),
		 ml("even", {mv("M")})}
   return datalog.assert(mr(head, body))
end

-- Assert the rules

function rules()
   even_base_case()
   even_inductive_case()
   odd_inductive_case()
end

-- PRIMITIVE

-- The successor relation as a primitive

function prim()
   local function succ(literal)
      return function(s, v)
		if v then
		   return nil
		else
		   local x = literal[1]
		   local y = literal[2]
		   if y:is_const() then
		      local j = tonumber(y.id)
		      if j and j >= 0 then
			 return {j + 1, j}
		      else
			 return nil
		      end
		   elseif x:is_const() then
		      local i = tonumber(x.id)
		      if i and i > 0 then
			 return {i, i - 1}
		      else
			 return nil
		      end
		   else
		      return nil
		   end
		end
	     end
   end
   return datalog.add_iter_prim("succ", 2, succ)
end

-- Compose the query

function ask_even(n)
   return ask(ml("even", {mc(n)}))
end

-- Usage as a stand-alone script:

-- lua even.lua [NUMBER]
-- Asks even(NUMBER) or asks even(1999) by default.

function main(arg)
   local number = 2000
   if arg[1] then
      number = arg[1]
   end
   rules()
   prim()

   io.write(string.format("even(%d)?\n", number))
   -- local start = os.clock()
   ask_even(number)
   -- io.write(string.format("CPU time %d sec\n", os.clock() - start))
end

if arg then
   return main(arg)
end
