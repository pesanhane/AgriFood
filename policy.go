
package main

func ABACPolicyAllows(sa SA, oa OA, pa int, ea EA) bool {
    return pa == 1 && ea.LimitDistance <= 1000
}
