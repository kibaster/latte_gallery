def f1(nums: list[int]):
    for i in nums:
        if i == 0:
            nums.remove(i)
            nums.append(i)
    return nums
def f2(s1,s2):
    return ''.join([x+y for x,y in zip(s1,s2)])
def f3(candies,extracandies):
    return list([(x+extracandies)>=max(candies) for x in candies])
print(f1([0,1,0,13,2]))
print(f2('abc','pqr'))
print(f3([2,3,5,1,3],3))