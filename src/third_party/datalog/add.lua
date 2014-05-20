local function add(literal)
   return function(s, v)
	     if v then
		return nil
	     else
		local x = literal[1]
		local y = literal[2]
		local z = literal[3]
		if y:is_const() and z:is_const() then
                   local j = tonumber(y.id)
                   local k = tonumber(z.id)
                   if j and k then
                      return {j + k, j, k}
                   else
                      return nil
                   end
		elseif x:is_const() and z:is_const() then
                   local i = tonumber(x.id)
                   local k = tonumber(z.id)
                   if i and k then
                      return {i, i - k, k}
                   else
                      return nil
                   end
		elseif x:is_const() and y:is_const() then
                   local i = tonumber(x.id)
                   local j = tonumber(y.id)
                   if i and j then
                      return {i, j, i - j}
                   else
                      return nil
                   end
		else
		   return nil
		end
	     end
	  end
end

datalog.add_iter_prim("add", 3, add)
