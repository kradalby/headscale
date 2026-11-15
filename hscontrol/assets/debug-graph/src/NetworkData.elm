module NetworkData exposing (..)

import Json.Decode as D exposing (Decoder)


type alias Object =
    { id : String, kind : String, label : String, nodeId : String, addresses : List String, ownerId : String, tags : List String, online : Maybe Bool, expired : Bool, relatedIds : List String, provenance : String, protocol : String, firstPort : Int, lastPort : Int, advertised : Bool, approved : Bool, sourceVisible : Bool, selected : Bool }


type alias Rule =
    { pointer : String, digest : String, excerpt : String, comments : String, line : Int, truncated : Bool, sourceMatch : Maybe Membership, destinationMatch : Maybe Membership }


type alias Membership =
    { selector : String, kind : String, address : String, nodeId : String, ownership : String, userId : String }


type alias Range =
    { source : String, destination : String, protocols : List Int, first : Int, last : Int, capabilities : List String }


type alias Capability =
    { name : String, rules : List Rule }


type alias Check =
    { rule : Rule, reason : String }


type alias Policy =
    { packet : String, ssh : String, reason : String, diagnostic : String, rules : List Rule, sshRules : List Rule, checks : List Check, checksTotal : Int, checksOmitted : Int, rulesTotal : Int, rulesOmitted : Int, capabilities : List Capability, evidenceOffset : Int, evidenceNext : Maybe Int, sshRulesTotal : Int, capabilitiesTotal : Int }


type alias Relationship =
    { source : String, target : String, kind : String }


type alias Access =
    { node : Object, ranges : List Range, capabilities : List String, visible : Bool, error : String }


type alias Result =
    { sourceIP : String, destinationIP : String, routerId : String, visible : Bool, routeEvidence : List Object, policy : Policy, evidenceSelected : Bool }


type Response
    = Inventory { revision : String, timestamp : String, total : Int, matched : Int, nextOffset : Maybe Int, items : List Object }
    | Topology { revision : String, timestamp : String, objects : List Object, relationships : List Relationship, omitted : Int }
    | AccessPage { revision : String, timestamp : String, total : Int, matched : Int, nextOffset : Maybe Int, items : List Access }
    | SourceChunk { revision : String, pointer : String, offset : Int, total : Int, nextOffset : Maybe Int, text : String }
    | Explanation { revision : String, timestamp : String, source : Object, destination : Object, results : List Result, observation : String, routing : String }


required : String -> Decoder a -> Decoder (a -> b) -> Decoder b
required name decoder accumulated =
    D.map2 (\fn value -> fn value) accumulated (D.field name decoder)


list : Decoder a -> Decoder (List a)
list decoder =
    D.oneOf [ D.list decoder, D.null [] ]


object : Decoder Object
object =
    D.succeed Object
        |> required "id" D.string
        |> required "kind" D.string
        |> required "label" D.string
        |> required "nodeId" D.string
        |> required "addresses" (list D.string)
        |> required "ownerId" D.string
        |> required "tags" (list D.string)
        |> required "online" (D.nullable D.bool)
        |> required "expired" D.bool
        |> required "relatedIds" (list D.string)
        |> required "provenance" D.string
        |> required "protocol" D.string
        |> required "firstPort" D.int
        |> required "lastPort" D.int
        |> required "advertised" D.bool
        |> required "approved" D.bool
        |> required "sourceVisible" D.bool
        |> required "selected" D.bool


rule : Decoder Rule
rule =
    D.succeed Rule
        |> required "pointer" D.string
        |> required "digest" D.string
        |> required "excerpt" D.string
        |> required "comments" (D.oneOf [ D.string, D.map (String.join "\n") (list D.string) ])
        |> required "line" D.int
        |> required "truncated" D.bool
        |> optional "sourceMatch" (D.nullable membership) Nothing
        |> optional "destinationMatch" (D.nullable membership) Nothing


optional : String -> Decoder a -> a -> Decoder (a -> b) -> Decoder b
optional name decoder fallback accumulated =
    D.map2 (\fn value -> fn value) accumulated (D.oneOf [ D.field name decoder, D.succeed fallback ])


membership : Decoder Membership
membership =
    D.succeed Membership
        |> required "selector" D.string
        |> required "kind" D.string
        |> required "address" D.string
        |> required "nodeId" D.string
        |> required "ownership" D.string
        |> required "userId" D.string


range : Decoder Range
range =
    D.succeed Range
        |> required "source" D.string
        |> required "destination" D.string
        |> required "protocols" (list D.int)
        |> required "first" D.int
        |> required "last" D.int
        |> required "capabilities" (list D.string)


capability : Decoder Capability
capability =
    D.map2 Capability (D.field "name" D.string) (D.field "rules" (list rule))


policy : Decoder Policy
policy =
    D.succeed Policy
        |> required "packet" D.string
        |> required "ssh" D.string
        |> required "reason" D.string
        |> required "diagnostic" D.string
        |> required "rules" (list rule)
        |> required "sshRules" (list rule)
        |> required "checks" (list (D.map2 Check (D.field "rule" rule) (D.field "reason" D.string)))
        |> required "checksTotal" D.int
        |> required "checksOmitted" D.int
        |> required "rulesTotal" D.int
        |> required "rulesOmitted" D.int
        |> required "capabilities" (list capability)
        |> required "evidenceOffset" D.int
        |> required "evidenceNext" (D.nullable D.int)
        |> required "sshRulesTotal" D.int
        |> required "capabilitiesTotal" D.int


relationship : Decoder Relationship
relationship =
    D.map3 Relationship (D.field "source" D.string) (D.field "target" D.string) (D.field "kind" D.string)


access : Decoder Access
access =
    D.succeed Access
        |> required "node" object
        |> required "ranges" (list range)
        |> required "capabilities" (list D.string)
        |> required "visible" D.bool
        |> required "error" D.string


result : Decoder Result
result =
    D.succeed Result
        |> required "sourceIP" D.string
        |> required "destinationIP" D.string
        |> required "routerId" D.string
        |> required "visible" D.bool
        |> required "routeEvidence" (list object)
        |> required "policy" policy
        |> required "evidenceSelected" D.bool


responseDecoder : String -> Decoder Response
responseDecoder operation =
    case operation of
        "inventory" ->
            D.map6 (\revision timestamp total matched nextOffset items -> Inventory { revision = revision, timestamp = timestamp, total = total, matched = matched, nextOffset = nextOffset, items = items }) (D.field "revision" D.string) (D.field "timestamp" D.string) (D.field "total" D.int) (D.field "matched" D.int) (D.field "nextOffset" (D.nullable D.int)) (D.field "items" (list object))

        "topology" ->
            D.map5 (\revision timestamp objects relationships omitted -> Topology { revision = revision, timestamp = timestamp, objects = objects, relationships = relationships, omitted = omitted }) (D.field "revision" D.string) (D.field "timestamp" D.string) (D.field "objects" (list object)) (D.field "relationships" (list relationship)) (D.field "omitted" D.int)

        "access" ->
            D.map6 (\revision timestamp total matched nextOffset items -> AccessPage { revision = revision, timestamp = timestamp, total = total, matched = matched, nextOffset = nextOffset, items = items }) (D.field "revision" D.string) (D.field "timestamp" D.string) (D.field "total" D.int) (D.field "matched" D.int) (D.field "nextOffset" (D.nullable D.int)) (D.field "items" (list access))

        "source" ->
            D.map6 (\revision pointer offset total nextOffset text -> SourceChunk { revision = revision, pointer = pointer, offset = offset, total = total, nextOffset = nextOffset, text = text }) (D.field "revision" D.string) (D.field "pointer" D.string) (D.field "offset" D.int) (D.field "total" D.int) (D.field "nextOffset" (D.nullable D.int)) (D.field "text" D.string)

        "explain" ->
            D.map7 (\revision timestamp source destination results observation routing -> Explanation { revision = revision, timestamp = timestamp, source = source, destination = destination, results = results, observation = observation, routing = routing }) (D.field "revision" D.string) (D.field "timestamp" D.string) (D.field "source" object) (D.field "destination" object) (D.field "results" (list result)) (D.field "observation" D.string) (D.field "routing" D.string)

        _ ->
            D.fail "Unknown Network operation"


responseRevision : Response -> String
responseRevision response =
    case response of
        Inventory data ->
            data.revision

        Topology data ->
            data.revision

        AccessPage data ->
            data.revision

        Explanation data ->
            data.revision

        SourceChunk data ->
            data.revision
