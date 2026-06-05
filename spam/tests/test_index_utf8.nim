import spam

let
  previous = "/𝔞"
  current = "/𝔟"
  shared = sharedPrefixLen(previous, current)

doAssert shared == 1
doAssert current[shared .. ^1] == "𝔟"

let
  sameScalarPrevious = "/𝔞-a"
  sameScalarCurrent = "/𝔞-b"
  sameScalarShared = sharedPrefixLen(sameScalarPrevious, sameScalarCurrent)

doAssert sameScalarShared == "/𝔞-".len
doAssert sameScalarCurrent[sameScalarShared .. ^1] == "b"
