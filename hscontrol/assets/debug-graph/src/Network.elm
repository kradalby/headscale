module Network exposing (Model, Msg(..), incoming, initial, load, update, view)

import Html as H exposing (Html)
import Html.Attributes as A
import Html.Events as Events
import Json.Decode as D
import Json.Encode as E
import NetworkData as Data exposing (Response(..))
import NetworkTopology


type alias Model =
    { evidenceOffset : Int, evidenceResult : Int, sourcePointer : String, sourceOffset : Int, operation : String, category : String, search : String, identity : String, selected : Maybe Data.Object, revision : String, generation : Int, offset : Int, accessProtocol : String, accessPort : String, accessIdentity : String, direction : String, source : String, sourceIP : String, destination : String, protocol : String, port_ : String, sshUser : String, response : Maybe Response, error : String, loading : Bool }


type Msg
    = Category String
    | Search String
    | Submit
    | Select Data.Object
    | TopologyFor Data.Object
    | AccessFor String Data.Object
    | Direction String
    | Page Int
    | Refresh
    | InventoryMode
    | Field String String
    | Explain
    | EvidencePage Int Int
    | SourcePage String Int


initial : Model
initial =
    { evidenceOffset = 0, evidenceResult = 0, sourcePointer = "", sourceOffset = 0, operation = "inventory", category = "nodes", search = "", identity = "", selected = Nothing, revision = "", generation = 0, offset = 0, accessProtocol = "", accessPort = "", accessIdentity = "", direction = "outgoing", source = "", sourceIP = "", destination = "", protocol = "6", port_ = "443", sshUser = "", response = Nothing, error = "", loading = False }


load : Int -> Model -> ( Model, E.Value )
load generation model =
    let
        fields =
            case model.operation of
                "inventory" ->
                    [ ( "category", model.category ), ( "search", model.search ), ( "identity", model.identity ), ( "offset", String.fromInt model.offset ), ( "limit", "50" ), ( "revision", model.revision ) ]

                "topology" ->
                    [ ( "id", Maybe.map .id model.selected |> Maybe.withDefault "" ), ( "revision", model.revision ) ]

                "access" ->
                    [ ( "id", Maybe.map .id model.selected |> Maybe.withDefault "" ), ( "identity", model.accessIdentity ), ( "protocol", model.accessProtocol ), ( "port", model.accessPort ), ( "direction", model.direction ), ( "search", model.search ), ( "offset", String.fromInt model.offset ), ( "limit", "50" ), ( "revision", model.revision ) ]

                "source" ->
                    [ ( "pointer", model.sourcePointer ), ( "offset", String.fromInt model.sourceOffset ), ( "revision", model.revision ) ]

                _ ->
                    [ ( "evidenceOffset", String.fromInt model.evidenceOffset )
                    , ( "evidenceResult", String.fromInt model.evidenceResult )
                    , ( "source", model.source )
                    , ( "sourceIP", model.sourceIP )
                    , ( "destination", model.destination )
                    , ( "protocol", model.protocol )
                    , ( "port"
                      , if List.member model.protocol [ "6", "17", "132" ] then
                            model.port_

                        else
                            ""
                      )
                    , ( "sshUser", model.sshUser )
                    , ( "revision", model.revision )
                    ]
    in
    ( { model | generation = generation, loading = True, error = "", response = Nothing }
    , E.object [ ( "action", E.string "network" ), ( "generation", E.int generation ), ( "operation", E.string model.operation ), ( "fields", E.object (List.map (Tuple.mapSecond E.string) fields) ) ]
    )


update : Msg -> Model -> ( Model, Bool )
update msg model =
    case msg of
        Category category ->
            ( { model | operation = "inventory", category = category, offset = 0, identity = "", search = "" }, True )

        Search search ->
            ( { model | search = search }, False )

        Submit ->
            ( { model | offset = 0 }, True )

        Select object ->
            ( { model | selected = Just object }, False )

        TopologyFor object ->
            ( { model | selected = Just object, operation = "topology", offset = 0 }, True )

        AccessFor direction object ->
            if object.kind == "node" then
                ( { model | selected = Just object, operation = "access", direction = direction, offset = 0, search = "" }, True )

            else
                ( { model | operation = "inventory", category = "nodes", identity = object.id, offset = 0, search = "" }, True )

        Direction direction ->
            ( { model | direction = direction, offset = 0 }, True )

        Page offset ->
            ( { model | offset = offset }, True )

        Refresh ->
            ( { model | revision = "", operation = "inventory", offset = 0, selected = Nothing }, True )

        InventoryMode ->
            ( { model | operation = "inventory", offset = 0 }, True )

        Field field value ->
            ( case field of
                "accessIdentity" ->
                    { model | accessIdentity = value }

                "accessProtocol" ->
                    { model | accessProtocol = value, accessPort = "" }

                "accessPort" ->
                    { model | accessPort = value }

                "source" ->
                    { model | source = value }

                "sourceIP" ->
                    { model | sourceIP = value }

                "destination" ->
                    { model | destination = value }

                "protocol" ->
                    { model | protocol = value }

                "port" ->
                    { model | port_ = value }

                "sshUser" ->
                    { model | sshUser = value }

                _ ->
                    model
            , False
            )

        EvidencePage result offset ->
            ( { model | operation = "explain", evidenceResult = result, evidenceOffset = offset }, True )

        SourcePage pointer offset ->
            ( { model | operation = "source", sourcePointer = pointer, sourceOffset = offset }, True )

        Explain ->
            if model.source == "" || model.destination == "" then
                ( { model | error = "Choose a concrete source node and a destination node or address." }, False )

            else if String.toInt model.protocol |> Maybe.map (\protocolNumber -> protocolNumber < 0 || protocolNumber > 255) |> Maybe.withDefault True then
                ( { model | error = "Enter an IP protocol from 0 to 255." }, False )

            else if List.member model.protocol [ "6", "17", "132" ] && (String.toInt model.port_ |> Maybe.map (\portNumber -> portNumber < 0 || portNumber > 65535) |> Maybe.withDefault True) then
                ( { model | error = "Enter a port from 0 to 65535." }, False )

            else
                ( { model | operation = "explain", evidenceOffset = 0, evidenceResult = 0 }, True )


incoming : D.Value -> Model -> Model
incoming value model =
    case D.decodeValue (D.field "generation" D.int) value of
        Ok generation ->
            if generation /= model.generation then
                model

            else
                case D.decodeValue (D.field "type" D.string) value of
                    Ok "network" ->
                        case D.decodeValue (D.field "data" (Data.responseDecoder model.operation)) value of
                            Ok response ->
                                { model | response = Just response, revision = Data.responseRevision response, loading = False, error = "" }

                            Err error ->
                                { model | error = D.errorToString error, loading = False }

                    Ok "networkError" ->
                        { model | error = D.decodeValue (D.field "data" D.string) value |> Result.withDefault "Request failed. Refresh the Network snapshot.", loading = False }

                    _ ->
                        model

        Err _ ->
            model


button : String -> Msg -> Html Msg
button label msg =
    H.button [ A.type_ "button", Events.onClick msg ] [ H.text label ]


view : Model -> Html Msg
view model =
    H.main_ [ A.class "network", A.id "network-main" ]
        [ H.div [ A.class "network-heading" ]
            [ H.div [] [ H.h1 [] [ H.text "Network" ], H.p [] [ H.text "Inventory, relationships and directional policy access" ] ]
            , button "Refresh Network" Refresh
            ]
        , H.p [ A.class "network-revision" ]
            [ H.text
                (if model.revision == "" then
                    "Requesting a snapshot"

                 else
                    "Snapshot " ++ model.revision ++ " · explicit refresh"
                )
            ]
        , H.nav [ A.class "network-tabs", A.attribute "aria-label" "Inventory categories" ]
            (List.map
                (\category ->
                    H.button
                        [ A.type_ "button"
                        , A.attribute "aria-pressed"
                            (if model.operation == "inventory" && model.category == category then
                                "true"

                             else
                                "false"
                            )
                        , Events.onClick (Category category)
                        ]
                        [ H.text category ]
                )
                [ "nodes", "users", "tags", "routes", "services" ]
            )
        , H.div [ A.class "network-workspace" ]
            [ H.section [ A.class "network-results" ]
                [ if model.operation == "inventory" || model.operation == "access" then
                    H.form [ A.class "search", Events.onSubmit Submit ] [ H.input [ A.type_ "search", A.value model.search, A.maxlength 512, A.placeholder "Search the complete inventory", A.attribute "aria-label" "Search complete inventory or access candidates", Events.onInput Search ] [], H.button [ A.type_ "submit" ] [ H.text "Search" ] ]

                  else
                    button "Back to inventory" InventoryMode
                , if model.operation == "access" then
                    H.div [ A.class "network-tabs" ] [ button "Outgoing access" (Direction "outgoing"), button "Incoming access" (Direction "incoming"), H.p [] [ H.text (model.direction ++ " · " ++ (Maybe.map .label model.selected |> Maybe.withDefault "")) ] ]

                  else
                    H.text ""
                , if model.operation == "access" then
                    H.form [ A.class "network-access-filters", Events.onSubmit Submit ]
                        [ H.label [] [ H.text "Identity ID", H.input [ A.value model.accessIdentity, A.placeholder "user:1 or tag:tag:web", Events.onInput (Field "accessIdentity") ] [] ]
                        , H.label [] [ H.text "IP protocol", H.input [ A.value model.accessProtocol, A.placeholder "All, or 0–255", Events.onInput (Field "accessProtocol") ] [] ]
                        , H.label [] [ H.text "Port", H.input [ A.value model.accessPort, A.disabled (not (List.member model.accessProtocol [ "6", "17", "132" ])), A.placeholder "All, or 0–65535", Events.onInput (Field "accessPort") ] [] ]
                        , H.button [ A.type_ "submit" ] [ H.text "Filter access" ]
                        , H.p [] [ H.text "Pages count candidate nodes. Empty ranges mean no packet range for these filters; capabilities remain separate." ]
                        ]

                  else
                    H.text ""
                , H.p [ A.attribute "role" "status" ]
                    [ H.text
                        (if model.loading then
                            "Loading snapshot…"

                         else
                            ""
                        )
                    ]
                , if model.error /= "" then
                    H.div [ A.class "error", A.attribute "role" "alert" ] [ H.text model.error, button "Refresh Network" Refresh ]

                  else
                    H.text ""
                , Maybe.map (responseView model) model.response |> Maybe.withDefault (H.text "")
                ]
            , H.aside [ A.class "network-inspector", A.attribute "aria-label" "Network selection and connection explanation" ]
                [ Maybe.map objectInspector model.selected |> Maybe.withDefault (H.p [] [ H.text "Select an object to inspect its identity and relationships." ])
                , explanationForm model
                ]
            ]
        , H.p [ A.class "semantic-note" ] [ H.text "Policy, peer visibility, route state and reported online state are separate facts. Live reachability and application listening state are unknown. No packet probe runs." ]
        ]


objectInspector : Data.Object -> Html Msg
objectInspector object =
    H.section []
        [ H.h2 [] [ H.text object.label ]
        , H.code [] [ H.text object.id ]
        , H.dl []
            [ H.dt [] [ H.text "Identity" ]
            , H.dd []
                [ H.text
                    (if List.isEmpty object.tags then
                        object.ownerId

                     else
                        String.join ", " object.tags
                    )
                ]
            , H.dt [] [ H.text "Addresses" ]
            , H.dd [] [ H.text (String.join ", " object.addresses) ]
            , H.dt [] [ H.text "Reported online" ]
            , H.dd []
                [ H.text
                    (Maybe.map
                        (\online ->
                            if online then
                                "Yes"

                            else
                                "No"
                        )
                        object.online
                        |> Maybe.withDefault "Unknown"
                    )
                ]
            , H.dt [] [ H.text "Expired" ]
            , H.dd []
                [ H.text
                    (if object.expired then
                        "Yes"

                     else
                        "No"
                    )
                ]
            , H.dt [] [ H.text "Provenance" ]
            , H.dd [] [ H.text object.provenance ]
            ]
        , H.div [ A.class "network-actions" ]
            [ button "Topology" (TopologyFor object)
            , button "Outgoing access" (AccessFor "outgoing" object)
            , button "Incoming access" (AccessFor "incoming" object)
            , if object.kind == "node" then
                button "Use as source" (Field "source" object.id)

              else
                H.text ""
            , if object.kind == "node" then
                button "Use as destination" (Field "destination" object.id)

              else
                H.text ""
            ]
        , if object.kind /= "node" then
            H.p [] [ H.text "Identity selection narrows the node inventory. Choose a concrete node for a verdict." ]

          else
            H.text ""
        , if object.kind == "route" then
            H.p [] [ H.text ("Advertised: " ++ bool object.advertised ++ " · approved: " ++ bool object.approved ++ " · selected: " ++ bool object.selected) ]

          else
            H.text ""
        , if object.kind == "service" then
            H.p [] [ H.text (object.protocol ++ " " ++ ports object.firstPort object.lastPort ++ " · " ++ object.provenance ++ ". Reported services are unverified observations; policy endpoints are permissions, not discovered applications.") ]

          else
            H.text ""
        ]


bool : Bool -> String
bool value =
    if value then
        "yes"

    else
        "no"


ports : Int -> Int -> String
ports first last =
    if first == 0 && last == 65535 then
        "*"

    else if first == last then
        String.fromInt first

    else
        String.fromInt first ++ "–" ++ String.fromInt last


objectCard : Data.Object -> Html Msg
objectCard object =
    H.li [ A.class "network-object" ] [ button object.label (Select object), H.small [] [ H.text (object.kind ++ " · " ++ String.join ", " object.addresses) ], button "Explore" (TopologyFor object) ]


pagination : Model -> Int -> Int -> Maybe Int -> Html Msg
pagination model total matched next =
    H.div [ A.class "network-pagination" ]
        [ H.p [] [ H.text (String.fromInt total ++ " total · " ++ String.fromInt matched ++ " matched · page starting at " ++ String.fromInt (model.offset + 1)) ]
        , H.button [ A.type_ "button", A.disabled (model.offset == 0), Events.onClick (Page (max 0 (model.offset - 50))) ] [ H.text "Previous" ]
        , H.button [ A.type_ "button", A.disabled (next == Nothing), Events.onClick (Page (Maybe.withDefault 0 next)) ] [ H.text "Next" ]
        ]


responseView : Model -> Response -> Html Msg
responseView model response =
    case response of
        Inventory data ->
            H.div [] [ H.p [] [ H.text (String.fromInt (List.length data.items) ++ " displayed · " ++ data.timestamp) ], H.ul [ A.class "network-list" ] (List.map objectCard data.items), pagination model data.total data.matched data.nextOffset ]

        Topology data ->
            let
                label id =
                    data.objects |> List.filter (\object -> object.id == id) |> List.head |> Maybe.map .label |> Maybe.withDefault id

                target id =
                    data.objects |> List.filter (\object -> object.id == id) |> List.head |> Maybe.map (\object -> button (label id) (TopologyFor object)) |> Maybe.withDefault (H.text id)
            in
            H.div []
                [ H.p [] [ H.text ("Bounded neighborhood · " ++ String.fromInt (List.length data.objects) ++ " objects · " ++ String.fromInt data.omitted ++ " omitted. Use inventory for every matching object.") ]
                , NetworkTopology.view TopologyFor data.objects data.relationships
                , H.h2 [] [ H.text "Relationships" ]
                , H.ul [ A.class "network-relationships" ] (List.map (\edge -> H.li [] [ target edge.source, H.span [] [ H.text (" → " ++ edge.kind ++ " → ") ], target edge.target ]) data.relationships)
                ]

        AccessPage data ->
            H.div []
                [ H.ul [ A.class "network-list" ]
                    (List.map
                        (\entry ->
                            H.li [ A.class "network-access" ]
                                [ button entry.node.label (Select entry.node)
                                , H.p [] [ H.text ("Peer visible: " ++ bool entry.visible) ]
                                , H.ul [] (List.map (\range -> H.li [] [ H.text (range.source ++ " → " ++ range.destination ++ " · IP protocol " ++ String.join ", " (List.map String.fromInt range.protocols) ++ " · ports " ++ ports range.first range.last) ]) entry.ranges)
                                , H.p [] [ H.text ("Application capabilities: " ++ String.join ", " entry.capabilities) ]
                                , H.p [] [ H.text entry.error ]
                                , button "Use as destination" (Field "destination" entry.node.id)
                                ]
                        )
                        data.items
                    )
                , pagination model data.total data.matched data.nextOffset
                ]

        Explanation data ->
            H.section [ A.class "network-explanation" ]
                [ H.h2 [] [ H.text "Connection explanation" ]
                , H.p [] [ H.text ("Source state · expired " ++ bool data.source.expired ++ " · reported online " ++ (Maybe.map bool data.source.online |> Maybe.withDefault "unknown")) ]
                , H.p [] [ H.text ("Destination state · expired " ++ bool data.destination.expired ++ " · reported online " ++ (Maybe.map bool data.destination.online |> Maybe.withDefault "unknown")) ]
                , H.p [] [ H.text data.routing ]
                , H.p [] [ H.text data.observation ]
                , H.div [] (List.indexedMap resultView data.results)
                ]

        SourceChunk data ->
            H.section []
                [ H.h2 [] [ H.text ("Original source " ++ data.pointer) ]
                , H.p [] [ H.text ("Bytes " ++ String.fromInt data.offset ++ "–" ++ String.fromInt (Maybe.withDefault data.total data.nextOffset) ++ " of " ++ String.fromInt data.total ++ ". Source and comments are shown incrementally at this snapshot revision.") ]
                , H.pre [] [ H.text data.text ]
                , button "First source chunk" (SourcePage data.pointer 0)
                , H.button [ A.type_ "button", A.disabled (data.nextOffset == Nothing), Events.onClick (SourcePage data.pointer (Maybe.withDefault 0 data.nextOffset)) ] [ H.text "Next source chunk" ]
                , button "Back to evidence" (EvidencePage model.evidenceResult model.evidenceOffset)
                ]


resultView : Int -> Data.Result -> Html Msg
resultView index result =
    H.article []
        [ H.h3 [] [ H.text (result.sourceIP ++ " → " ++ result.destinationIP) ]
        , H.p []
            [ H.text
                (if String.contains ":" result.destinationIP then
                    "IPv6 result"

                 else
                    "IPv4 result"
                )
            ]
        , H.dl [] [ H.dt [] [ H.text "Packet policy" ], H.dd [] [ H.text result.policy.packet ], H.dt [] [ H.text "Tailscale SSH" ], H.dd [] [ H.text result.policy.ssh ], H.dt [] [ H.text "Visibility" ], H.dd [] [ H.text (bool result.visible) ], H.dt [] [ H.text "Router" ], H.dd [] [ H.text result.routerId ] ]
        , H.p [] [ H.text result.policy.reason ]
        , H.p [] [ H.text result.policy.diagnostic ]
        , H.h4 [] [ H.text "Route evidence" ]
        , H.ul [] (List.map (\route -> H.li [] [ H.text (route.label ++ " · advertised " ++ bool route.advertised ++ " · approved " ++ bool route.approved ++ " · selected " ++ bool route.selected ++ " · source-visible " ++ bool route.sourceVisible) ]) result.routeEvidence)
        , button "Inspect evidence for this address/router result" (EvidencePage index 0)
        , if result.evidenceSelected then
            evidenceView index result.policy

          else
            H.p [] [ H.text "Select this result to inspect its independently paged evidence." ]
        ]


evidenceView : Int -> Data.Policy -> Html Msg
evidenceView index policy =
    H.section []
        [ H.h4 [] [ H.text "Contributing source rules" ]
        , H.div [] (List.map ruleView policy.rules)
        , H.p [] [ H.text (String.fromInt policy.rulesTotal ++ " contributing rules · " ++ String.fromInt policy.rulesOmitted ++ " omitted") ]
        , H.h4 [] [ H.text "Rule matching checks" ]
        , H.p [] [ H.text "Checks summarize the furthest condition across compiled contributions; they are not a unique cause or a suggested fix. Membership witnesses show one original selector resolving to each chosen address; pair-dependent self selectors are evaluated by the compiler." ]
        , H.p [] [ H.text (String.fromInt policy.checksTotal ++ " checked · " ++ String.fromInt policy.checksOmitted ++ " omitted") ]
        , H.div [] (List.map (\check -> H.section [] [ H.p [] [ H.text check.reason ], ruleView check.rule ]) policy.checks)
        , H.h4 [] [ H.text ("Tailscale SSH source rules · " ++ String.fromInt policy.sshRulesTotal ++ " total") ]
        , H.div [] (List.map ruleView policy.sshRules)
        , H.h4 [] [ H.text ("Application capability references · " ++ String.fromInt policy.capabilitiesTotal ++ " total (separate from packet permission)") ]
        , H.div [] (List.map (\capability -> H.section [] [ H.strong [] [ H.text capability.name ], H.div [] (List.map ruleView capability.rules) ]) policy.capabilities)
        , H.p [] [ H.text ("Evidence page starts at " ++ String.fromInt (policy.evidenceOffset + 1) ++ "; each evidence category pages independently in groups of 10. Capability names longer than 256 bytes are previewed; original source contains full names.") ]
        , H.button [ A.type_ "button", A.disabled (policy.evidenceOffset == 0), Events.onClick (EvidencePage index (max 0 (policy.evidenceOffset - 10))) ] [ H.text "Previous evidence" ]
        , H.button [ A.type_ "button", A.disabled (policy.evidenceNext == Nothing), Events.onClick (EvidencePage index (Maybe.withDefault 0 policy.evidenceNext)) ] [ H.text "Next evidence" ]
        ]


ruleView : Data.Rule -> Html Msg
ruleView rule =
    let
        witness side value =
            Maybe.map (\m -> H.p [] [ H.text (side ++ " selector " ++ m.selector ++ " (" ++ m.kind ++ ") resolves to " ++ m.address ++ " · node " ++ m.nodeId ++ " · ownership " ++ m.ownership ++ " · user " ++ m.userId) ]) value |> Maybe.withDefault (H.text "")
    in
    H.details []
        [ H.summary [] [ H.text (rule.pointer ++ " · line " ++ String.fromInt rule.line) ]
        , H.code [] [ H.text ("Source digest " ++ rule.digest) ]
        , witness "Source" rule.sourceMatch
        , witness "Destination" rule.destinationMatch
        , H.pre [] [ H.text rule.comments ]
        , H.pre [] [ H.text rule.excerpt ]
        , if rule.truncated then
            H.p [] [ H.text "Source preview truncated. Inspect original source for the complete rule and comments." ]

          else
            H.text ""
        , button "Inspect original source and comments" (SourcePage rule.pointer 0)
        ]


explanationForm : Model -> Html Msg
explanationForm model =
    let
        field label name value placeholder =
            H.label [] [ H.span [] [ H.text label ], H.input [ A.value value, A.placeholder placeholder, Events.onInput (Field name), A.maxlength 512 ] [] ]
    in
    H.form [ A.class "network-form", Events.onSubmit Explain ]
        [ H.h2 [] [ H.text "Explain a connection" ]
        , field "Source node ID" "source" model.source "node:1"
        , field "Source IP (optional)" "sourceIP" model.sourceIP "Explicit IPv4 or IPv6 address"
        , field "Destination node ID or address" "destination" model.destination "node:2 or 100.64.0.2"
        , H.label [] [ H.span [] [ H.text "IP protocol" ], H.select [ A.value model.protocol, Events.onInput (Field "protocol") ] (List.map (\( value, label ) -> H.option [ A.value value ] [ H.text label ]) [ ( "6", "TCP (6)" ), ( "17", "UDP (17)" ), ( "1", "ICMP (1)" ), ( "58", "ICMPv6 (58)" ), ( "132", "SCTP (132)" ), ( "47", "GRE (47)" ) ]) ]
        , field "Numeric IP protocol (0–255)" "protocol" model.protocol "6"
        , if List.member model.protocol [ "6", "17", "132" ] then
            field "Destination port" "port" model.port_ "443"

          else
            H.p [] [ H.text "This protocol has no destination port." ]
        , field "Tailscale SSH local username (optional)" "sshUser" model.sshUser "alice"
        , H.p [] [ H.text "SSH requires a destination node and local username. TCP/22 packet permission is evaluated separately. Node destinations produce separate IPv4 and IPv6 results." ]
        , H.button [ A.type_ "submit", A.disabled model.loading ] [ H.text "Explain connection" ]
        ]
