import math
import random

def generator(m, a, c, x0, n):
    nums = []
    curr_x = x0
    for _ in range(n):
        next_x = (a*curr_x + c)%m
        nums.append(next_x)
        curr_x = next_x
    return nums

def gcd(a,b):
    while b:
        a,b = b,a%b
    return a

def cesaro(nums):
    if len(nums) < 2:
        return 0

    count = 0
    total = 0
    for i in range(0, len(nums)-1, 2):
        total += 1
        if gcd(nums[i],nums[i+1]) == 1:
            count += 1

    if count == 0:
        return 0

    return math.sqrt((6*total)/count)

def period(m, a, c, x0):
    seen = {}
    curr_x = x0

    for i in range(m+1):
        next_x = (a*curr_x + c)%m

        if next_x in seen:
            return i - seen[next_x]

        seen[next_x] = i
        curr_x = next_x

    return m


def cesaro_rand(m, n):
    nums = [random.randint(0, m-1) for _ in range(n)]
    return cesaro(nums)

