module Network exposing (Model, Msg(..), controls, incoming, initial, load, update, view)

import Dict
import Html as H exposing (Html)
import Html.Attributes as A
import Html.Events as Events
import Json.Decode as D
import Json.Encode as E
import NetworkData as Data exposing (Response(..))
import NetworkTopology as Canvas
import Set exposing (Set)


type alias Model =
    { operation : String
    , category : String
    , search : String
    , identity : String
    , focus : String
    , selected : Maybe Data.Object
    , anchor : Maybe Data.Object
    , trail : List Data.Object
    , selectedEdge : Maybe Data.Relationship
    , revision : String
    , generation : Int
    , offset : Int
    , pageLimit : Int
    , nextOffset : Maybe Int
    , total : Int
    , matched : Int
    , omitted : Int
    , accessProtocol : String
    , accessPort : String
    , accessIdentity : String
    , direction : String
    , source : String
    , sourceIP : String
    , destination : String
    , protocol : String
    , port_ : String
    , sshUser : String
    , evidenceOffset : Int
    , evidenceResult : Int
    , sourcePointer : String
    , sourceOffset : Int
    , response : Maybe Response
    , error : String
    , loading : Bool
    , inspectorOpen : Bool
    , objects : List Data.Object
    , relationships : List Data.Relationship
    , access : List Data.Access
    , canvas : Canvas.Model
    , hidden : Set String
    , showBlocked : Bool
    , sceneMode : String
    }


type Msg
    = Search String
    | Submit
    | Select Data.Object
    | Explore Data.Object
    | BackTo Data.Object
    | SelectEdge Data.Relationship
    | TopologyFor Data.Object
    | AccessFor String Data.Object
    | Direction String
    | Page Int
    | Refresh
    | InventoryMode
    | Category String
    | Layer String
    | Blocked
    | CloseInspector
    | Field String String
    | Traffic String String
    | ConnectionTraffic String String
    | Explain
    | EvidencePage Int Int
    | SourcePage String Int
    | CanvasMsg Canvas.Msg


initial : Model
initial =
    { operation = "topology"
    , category = "nodes"
    , search = ""
    , identity = ""
    , focus = ""
    , selected = Nothing
    , anchor = Nothing
    , trail = []
    , selectedEdge = Nothing
    , revision = ""
    , generation = 0
    , offset = 0
    , pageLimit = 12
    , nextOffset = Nothing
    , total = 0
    , matched = 0
    , omitted = 0
    , accessProtocol = ""
    , accessPort = ""
    , accessIdentity = ""
    , direction = "outgoing"
    , source = ""
    , sourceIP = ""
    , destination = ""
    , protocol = "6"
    , port_ = "443"
    , sshUser = ""
    , evidenceOffset = 0
    , evidenceResult = 0
    , sourcePointer = ""
    , sourceOffset = 0
    , response = Nothing
    , error = ""
    , loading = False
    , inspectorOpen = False
    , objects = []
    , relationships = []
    , access = []
    , canvas = Canvas.init
    , hidden = Set.empty
    , showBlocked = False
    , sceneMode = "overview"
    }


pageSize : Model -> Int
pageSize model =
    if model.canvas.width < 600 then
        4

    else
        12


load : Int -> Model -> ( Model, E.Value )
load generation model =
    let
        fields =
            case model.operation of
                "inventory" ->
                    [ ( "category", model.category ), ( "search", model.search ), ( "identity", model.identity ), ( "offset", String.fromInt model.offset ), ( "limit", String.fromInt (pageSize model) ) ]

                "topology" ->
                    [ ( "id", model.focus ), ( "search", model.search ), ( "identity", model.identity ) ]

                "access" ->
                    [ ( "id", Maybe.map .id model.anchor |> Maybe.withDefault "" )
                    , ( "identity", model.accessIdentity )
                    , ( "protocol", model.accessProtocol )
                    , ( "port", model.accessPort )
                    , ( "direction", model.direction )
                    , ( "onlyPermitted"
                      , if model.showBlocked || model.search /= "" then
                            ""

                        else
                            "true"
                      )
                    , ( "search", model.search )
                    , ( "offset", String.fromInt model.offset )
                    , ( "limit", String.fromInt (pageSize model) )
                    ]

                "source" ->
                    [ ( "pointer", model.sourcePointer ), ( "offset", String.fromInt model.sourceOffset ) ]

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
                    ]
    in
    ( { model
        | generation = generation
        , loading = True
        , error = ""
        , response = Nothing
        , pageLimit =
            if List.member model.operation [ "inventory", "access" ] then
                pageSize model

            else
                model.pageLimit
      }
    , E.object [ ( "action", E.string "network" ), ( "generation", E.int generation ), ( "operation", E.string model.operation ), ( "fields", E.object (List.map (Tuple.mapSecond E.string) (( "revision", model.revision ) :: fields)) ) ]
    )


remember : Data.Object -> Model -> List Data.Object
remember object model =
    case model.anchor of
        Just previous ->
            if previous.id == object.id then
                model.trail

            else
                List.take 8 (previous :: List.filter (\item -> item.id /= previous.id && item.id /= object.id) model.trail)

        Nothing ->
            model.trail


earlier : String -> List Data.Object -> List Data.Object
earlier id trail =
    case trail of
        [] ->
            []

        first :: rest ->
            if first.id == id then
                rest

            else
                earlier id rest


explore : Data.Object -> Model -> ( Model, Bool )
explore object model =
    if object.kind == "node" then
        update (AccessFor "outgoing" object) model

    else if List.member object.kind [ "user", "tag" ] then
        ( { model | operation = "inventory", sceneMode = "members", category = "nodes", identity = object.id, focus = "", anchor = Just object, trail = remember object model, selected = Just object, selectedEdge = Nothing, search = "", offset = 0, response = Nothing, inspectorOpen = True }, True )

    else
        update (TopologyFor object) model


update : Msg -> Model -> ( Model, Bool )
update msg model =
    case msg of
        CanvasMsg action ->
            ( { model | canvas = Canvas.update action model.canvas }, False )

        Search search ->
            ( { model | search = search }, False )

        Submit ->
            ( { model
                | operation =
                    if model.sceneMode == "access" then
                        "access"

                    else if model.sceneMode == "members" then
                        "inventory"

                    else
                        "topology"
                , offset = 0
                , focus = ""
                , response = Nothing
                , selectedEdge = Nothing
                , sceneMode =
                    if List.member model.sceneMode [ "access", "members" ] then
                        model.sceneMode

                    else
                        "overview"
                , selected =
                    if List.member model.sceneMode [ "access", "members" ] then
                        model.anchor

                    else
                        Nothing
                , anchor =
                    if List.member model.sceneMode [ "access", "members" ] then
                        model.anchor

                    else
                        Nothing
                , trail =
                    if List.member model.sceneMode [ "access", "members" ] then
                        model.trail

                    else
                        []
              }
            , True
            )

        Category category ->
            ( { model | operation = "inventory", category = category, identity = "", offset = 0, sceneMode = "search", selected = Nothing, anchor = Nothing, search = "" }, True )

        Select object ->
            if model.sceneMode == "access" && object.kind == "node" && Maybe.map .id model.anchor /= Just object.id then
                let
                    edge =
                        model.relationships |> List.filter (\r -> r.source == object.id || r.target == object.id) |> List.head
                in
                case edge of
                    Just relationship ->
                        update (SelectEdge relationship) model

                    Nothing ->
                        explore object model

            else
                explore object model

        Explore object ->
            explore object model

        BackTo object ->
            explore object { model | anchor = Nothing, trail = earlier object.id model.trail }

        SelectEdge edge ->
            if model.sceneMode == "access" then
                let
                    targetId =
                        if model.direction == "incoming" then
                            edge.source

                        else
                            edge.target

                    entry =
                        model.access |> List.filter (\a -> a.node.id == targetId) |> List.head

                    range =
                        entry |> Maybe.andThen (.ranges >> List.filter (\r -> List.isEmpty r.capabilities) >> List.head)

                    protocol =
                        if model.accessProtocol /= "" then
                            model.accessProtocol

                        else
                            range |> Maybe.andThen (.protocols >> List.head) |> Maybe.map String.fromInt |> Maybe.withDefault "6"

                    port_ =
                        if model.accessPort /= "" then
                            model.accessPort

                        else
                            range
                                |> Maybe.map
                                    (\r ->
                                        if r.first == 0 && r.last == 65535 then
                                            "443"

                                        else
                                            String.fromInt r.first
                                    )
                                |> Maybe.withDefault "443"
                in
                update Explain { model | source = edge.source, sourceIP = "", destination = edge.target, protocol = protocol, port_ = port_, selected = entry |> Maybe.map .node, selectedEdge = Just edge, inspectorOpen = True, sshUser = "", response = Nothing }

            else
                case model.objects |> List.filter (\o -> o.id == edge.target) |> List.head of
                    Just object ->
                        ( { model | selected = Just object, selectedEdge = Just edge, inspectorOpen = True }, False )

                    Nothing ->
                        ( model, False )

        TopologyFor object ->
            ( { model | operation = "topology", sceneMode = "relationships", focus = object.id, identity = "", anchor = Just object, trail = remember object model, selected = Just object, selectedEdge = Nothing, search = "", offset = 0, response = Nothing, inspectorOpen = True }, True )

        AccessFor direction object ->
            if object.kind == "node" then
                ( { model | operation = "access", sceneMode = "access", direction = direction, anchor = Just object, trail = remember object model, selected = Just object, selectedEdge = Nothing, identity = "", search = "", offset = 0, response = Nothing, inspectorOpen = True }, True )

            else
                explore object model

        Direction direction ->
            ( { model | operation = "access", direction = direction, offset = 0, response = Nothing, selectedEdge = Nothing, selected = model.anchor, sourceIP = "" }, True )

        Page offset ->
            ( { model
                | operation =
                    if model.sceneMode == "access" then
                        "access"

                    else
                        "inventory"
                , offset = offset
                , response = Nothing
                , selectedEdge = Nothing
              }
            , True
            )

        Refresh ->
            ( { initial | generation = model.generation, canvas = model.canvas }, True )

        InventoryMode ->
            ( { initial | revision = model.revision, generation = model.generation, canvas = model.canvas }, True )

        Layer kind ->
            ( { model
                | hidden =
                    if Set.member kind model.hidden then
                        Set.remove kind model.hidden

                    else
                        Set.insert kind model.hidden
              }
            , False
            )

        Blocked ->
            ( { model | showBlocked = not model.showBlocked, operation = "access", offset = 0, selectedEdge = Nothing, selected = model.anchor, response = Nothing }, True )

        CloseInspector ->
            ( { model | inspectorOpen = False }, False )

        Traffic protocol port_ ->
            ( { model | operation = "access", accessProtocol = protocol, accessPort = port_, offset = 0, response = Nothing, selectedEdge = Nothing, selected = model.anchor }, True )

        ConnectionTraffic protocol port_ ->
            update Explain
                { model
                    | protocol = protocol
                    , port_ = port_
                    , sshUser =
                        if port_ == "22" then
                            "root"

                        else
                            ""
                }

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
                ( { model | error = "Select a device, then a connection on the graph." }, False )

            else if String.toInt model.protocol |> Maybe.map (\n -> n < 0 || n > 255) |> Maybe.withDefault True then
                ( { model | error = "IP protocol must be between 0 and 255." }, False )

            else if List.member model.protocol [ "6", "17", "132" ] && (String.toInt model.port_ |> Maybe.map (\n -> n < 0 || n > 65535) |> Maybe.withDefault True) then
                ( { model | error = "Port must be between 0 and 65535." }, False )

            else
                ( { model | operation = "explain", evidenceOffset = 0, evidenceResult = 0, inspectorOpen = True }, True )


setScene : List Data.Object -> List Data.Relationship -> Model -> Model
setScene objects relationships model =
    let
        unique =
            objects |> List.map (\o -> ( o.id, o )) |> Dict.fromList |> Dict.values

        ids =
            Set.fromList (List.map .id unique)

        edges =
            List.filter (\e -> Set.member e.source ids && Set.member e.target ids) relationships
    in
    { model | objects = unique, relationships = edges, canvas = Canvas.setScene unique edges model.canvas }


overview : List Data.Object -> List Data.Relationship -> Model -> Model
overview objects relationships model =
    let
        identities =
            List.filter (\o -> List.member o.kind [ "user", "tag" ]) objects

        devices =
            List.filter (\o -> o.kind == "node") objects

        samples =
            if model.canvas.width < 600 && not (List.isEmpty identities) then
                []

            else if List.isEmpty identities then
                List.take 24 devices

            else
                List.concatMap (\identity -> devices |> List.filter (\o -> List.member identity.id o.relatedIds) |> List.take 5) identities

        nodeIds =
            Set.fromList (List.map .id samples)

        endpoints =
            objects |> List.filter (\o -> List.member o.kind [ "route", "service" ] && List.any (\id -> Set.member id nodeIds) o.relatedIds) |> List.take 8
    in
    setScene (identities ++ samples ++ endpoints) relationships model


accessKind : Data.Access -> String
accessKind entry =
    if entry.error /= "" then
        "Unavailable"

    else if List.any (\r -> List.isEmpty r.capabilities) entry.ranges then
        "Packet access"

    else if not (List.isEmpty entry.capabilities) || List.any (\r -> not (List.isEmpty r.capabilities)) entry.ranges then
        "Capabilities only"

    else
        "No packet grant"


buildAccess : Model -> Model
buildAccess model =
    case model.anchor of
        Nothing ->
            model

        Just anchor ->
            let
                entries =
                    model.access |> List.filter (\a -> a.node.id /= anchor.id && (model.showBlocked || model.search /= "" || not (List.isEmpty a.ranges) || not (List.isEmpty a.capabilities) || a.error /= ""))

                edges =
                    entries
                        |> List.map
                            (\a ->
                                if model.direction == "incoming" then
                                    { source = a.node.id, target = anchor.id, kind = accessKind a }

                                else
                                    { source = anchor.id, target = a.node.id, kind = accessKind a }
                            )
            in
            setScene (anchor :: List.map .node entries) edges model


incoming : D.Value -> Model -> Model
incoming value model =
    if D.decodeValue (D.field "generation" D.int) value /= Ok model.generation then
        model

    else
        case D.decodeValue (D.field "type" D.string) value of
            Ok "geometry" ->
                case D.decodeValue (D.field "data" (D.map2 Tuple.pair (D.field "width" D.float) (D.field "height" D.float))) value of
                    Ok ( width, height ) ->
                        let
                            resized =
                                Canvas.update (Canvas.Resize width height) model.canvas

                            next =
                                { model
                                    | canvas =
                                        if (width < 600) /= (model.canvas.width < 600) then
                                            Canvas.layout model.objects resized

                                        else
                                            Canvas.fit model.objects resized
                                }
                        in
                        case model.response of
                            Just (Topology data) ->
                                if model.sceneMode == "overview" && model.search == "" then
                                    overview data.objects data.relationships next

                                else
                                    next

                            _ ->
                                next

                    Err _ ->
                        model

            Ok "network" ->
                case D.decodeValue (D.field "data" (Data.responseDecoder model.operation)) value of
                    Err error ->
                        { model | error = D.errorToString error, loading = False }

                    Ok response ->
                        let
                            next =
                                { model | response = Just response, revision = Data.responseRevision response, loading = False, error = "" }
                        in
                        case response of
                            Topology data ->
                                if model.sceneMode == "overview" && model.search == "" then
                                    overview data.objects data.relationships { next | omitted = data.omitted }

                                else
                                    setScene data.objects data.relationships { next | omitted = data.omitted }

                            Inventory data ->
                                let
                                    anchors =
                                        Maybe.map List.singleton model.anchor |> Maybe.withDefault []

                                    edges =
                                        data.items |> List.concatMap (\o -> List.map (\id -> { source = o.id, target = id, kind = "Identity" }) o.relatedIds)
                                in
                                setScene (anchors ++ data.items) edges { next | total = data.total, matched = data.matched, nextOffset = data.nextOffset, omitted = 0 }

                            AccessPage data ->
                                buildAccess { next | access = data.items, total = data.total, matched = data.matched, nextOffset = data.nextOffset, omitted = 0 }

                            Explanation data ->
                                case model.selectedEdge of
                                    Nothing ->
                                        next

                                    Just edge ->
                                        let
                                            verdicts =
                                                List.map (.policy >> .packet) data.results |> Set.fromList |> Set.toList

                                            verdict =
                                                case verdicts of
                                                    [ only ] ->
                                                        only

                                                    _ ->
                                                        "mixed results"

                                            label =
                                                (if model.protocol == "6" then
                                                    "TCP"

                                                 else if model.protocol == "17" then
                                                    "UDP"

                                                 else
                                                    "IP " ++ model.protocol
                                                )
                                                    ++ (if List.member model.protocol [ "6", "17", "132" ] then
                                                            " " ++ model.port_

                                                        else
                                                            ""
                                                       )
                                                    ++ " · "
                                                    ++ verdict

                                            inspected =
                                                { edge | kind = label }
                                        in
                                        { next
                                            | selectedEdge = Just inspected
                                            , relationships =
                                                List.map
                                                    (\r ->
                                                        if r.source == edge.source && r.target == edge.target then
                                                            inspected

                                                        else
                                                            r
                                                    )
                                                    model.relationships
                                        }

                            _ ->
                                next

            Ok "networkError" ->
                { model | error = D.decodeValue (D.field "data" D.string) value |> Result.withDefault "Unable to load this snapshot. Refresh to try again.", loading = False }

            _ ->
                model


button : String -> Msg -> Html Msg
button label msg =
    H.button [ A.type_ "button", Events.onClick msg ] [ H.text label ]


pressed : String -> Bool -> Msg -> Html Msg
pressed label active msg =
    H.button
        [ A.type_ "button"
        , A.attribute "aria-pressed"
            (if active then
                "true"

             else
                "false"
            )
        , Events.onClick msg
        ]
        [ H.text label ]


controls : Model -> Html Msg
controls model =
    H.div [ A.class "network-toolbar-controls" ]
        [ H.form [ A.class "search", Events.onSubmit Submit ]
            [ H.input
                [ A.type_ "search"
                , A.placeholder
                    (if model.sceneMode == "access" then
                        "Find a destination, including blocked devices…"

                     else
                        "Find a device, identity, route or service…"
                    )
                , A.attribute "aria-label" "Search network"
                , A.value model.search
                , A.maxlength 512
                , Events.onInput Search
                ]
                []
            , H.button [ A.type_ "submit" ] [ H.text "Search" ]
            ]
        , H.span [ A.class "connection", A.attribute "role" "status" ]
            [ H.span
                [ A.class
                    (if model.loading then
                        "status-dot"

                     else
                        "status-dot live"
                    )
                ]
                []
            , H.text
                (if model.loading then
                    "Loading"

                 else
                    "Snapshot"
                )
            ]
        , button "Refresh" Refresh
        ]


view : Model -> Html Msg
view model =
    let
        objects =
            model.objects |> List.filter (\o -> not (Set.member o.kind model.hidden))

        ids =
            Set.fromList (List.map .id objects)

        relationships =
            model.relationships |> List.filter (\e -> Set.member e.source ids && Set.member e.target ids)

        anchorLabel =
            Maybe.map .label model.anchor |> Maybe.withDefault "Network"

        title =
            if model.sceneMode == "access" then
                (if model.direction == "incoming" then
                    "Access to "

                 else
                    "Access from "
                )
                    ++ anchorLabel

            else if model.sceneMode == "members" then
                anchorLabel

            else if model.sceneMode == "relationships" then
                "Around " ++ anchorLabel

            else
                "Your network"
    in
    H.div [ A.class "workspace network-workspace", A.id "network-main" ]
        [ H.aside [ A.class "sidebar network-sidebar", A.attribute "aria-label" "Network exploration" ]
            [ H.h2 [] [ H.text "Explore" ]
            , H.div [ A.class "network-scope" ] [ pressed "Whole network" (model.sceneMode == "overview") InventoryMode ]
            , if model.sceneMode == "access" then
                H.section [ A.class "network-lens" ]
                    [ H.h2 [] [ H.text "Direction" ]
                    , pressed "Outgoing access" (model.direction == "outgoing") (Direction "outgoing")
                    , pressed "Incoming access" (model.direction == "incoming") (Direction "incoming")
                    , H.h2 [] [ H.text "Traffic" ]
                    , H.div [ A.class "network-presets" ] (List.map (\( label, protocol, port_ ) -> pressed label (model.accessProtocol == protocol && model.accessPort == port_) (Traffic protocol port_)) [ ( "Any", "", "" ), ( "HTTPS", "6", "443" ), ( "SSH", "6", "22" ), ( "DNS", "17", "53" ) ])
                    , H.label [ A.class "network-check" ] [ H.input [ A.type_ "checkbox", A.checked model.showBlocked, Events.onCheck (\_ -> Blocked) ] [], H.text "Show blocked candidates" ]
                    ]

              else
                H.text ""
            , H.h2 [] [ H.text "Show on graph" ]
            , H.div [ A.class "network-layers" ] (List.map (\( kind, label ) -> H.label [ A.class ("network-check " ++ kind) ] [ H.input [ A.type_ "checkbox", A.checked (not (Set.member kind model.hidden)), Events.onCheck (\_ -> Layer kind) ] [], H.span [ A.class ("swatch " ++ kind) ] [], H.text label ]) [ ( "node", "Devices" ), ( "user", "People" ), ( "tag", "Tags" ), ( "route", "Routes" ), ( "service", "Services" ) ])
            , H.div [ A.class "network-reading-key" ] [ H.h2 [] [ H.text "Connections" ], H.p [] [ H.span [ A.class "edge-key structural" ] [], H.text "Ownership / relationship" ], H.p [] [ H.span [ A.class "edge-key allowed" ] [], H.text "Packet access" ], H.p [] [ H.span [ A.class "edge-key denied" ] [], H.text "No packet grant" ] ]
            , H.p [ A.class "sidebar-note" ] [ H.text "Click an identity to explore its devices. Click a device to follow access. Click a connection to understand why." ]
            ]
        , H.main_ [ A.class "scene-panel network-scene" ]
            [ H.div [ A.class "scene-heading" ]
                [ H.div []
                    [ H.nav [ A.class "network-breadcrumb", A.attribute "aria-label" "Exploration path" ]
                        ([ button "Network" InventoryMode ]
                            ++ List.concatMap (\object -> [ H.span [] [ H.text "/" ], button object.label (BackTo object) ]) (List.reverse model.trail)
                            ++ [ if model.anchor /= Nothing then
                                    H.span [] [ H.text ("/ " ++ anchorLabel) ]

                                 else
                                    H.text ""
                               ]
                        )
                    , H.h1 [] [ H.text title ]
                    , H.p []
                        [ H.text
                            (if model.sceneMode == "overview" then
                                if model.canvas.width < 600 then
                                    "Select an identity to explore its devices."

                                else
                                    "Identity groups and a sample of their devices. Select a group to go deeper."

                             else if model.sceneMode == "access" then
                                "Follow a connection to inspect its policy, ports and visibility."

                             else
                                "Explore the objects and relationships in this neighborhood."
                            )
                        ]
                    ]
                , H.span [ A.class "revision", A.title model.revision ] [ H.text ("Revision " ++ (String.split ":" model.revision |> List.reverse |> List.head |> Maybe.withDefault "—")) ]
                ]
            , if model.error /= "" then
                H.div [ A.class "banner error", A.attribute "role" "alert" ] [ H.text model.error, button "Refresh" Refresh ]

              else
                H.text ""
            , H.div
                [ A.class "network-canvas-area"
                , A.attribute "aria-busy"
                    (if model.loading then
                        "true"

                     else
                        "false"
                    )
                ]
                [ Canvas.view { onMsg = CanvasMsg, onSelect = Select, onEdge = SelectEdge, selected = Maybe.map .id model.selected, selectedEdge = model.selectedEdge } objects relationships model.canvas
                , if model.loading then
                    H.div [ A.class "network-canvas-loading", A.attribute "role" "status" ] [ H.text "Updating graph…" ]

                  else
                    H.text ""
                , if List.isEmpty objects && not model.loading then
                    H.div [ A.class "empty" ] [ H.h2 [] [ H.text "No objects in this view" ], H.p [] [ H.text "Try another search or return to the whole network." ], button "Whole network" InventoryMode ]

                  else
                    H.text ""
                , if model.sceneMode == "access" && List.isEmpty relationships && not model.loading then
                    H.div [ A.class "network-empty-access" ]
                        [ H.text "No permitted connections for these filters."
                        , button "Show blocked candidates" Blocked
                        , if model.nextOffset /= Nothing then
                            button "Next devices" (Page (Maybe.withDefault 0 model.nextOffset))

                          else
                            H.text ""
                        ]

                  else
                    H.text ""
                ]
            , H.footer [ A.class "scene-footer network-footer" ]
                [ H.span [] [ H.text (String.fromInt (List.length objects) ++ " objects · " ++ String.fromInt (List.length relationships) ++ " connections") ]
                , if List.member model.sceneMode [ "members", "access", "search" ] then
                    H.div [ A.class "network-pagination" ]
                        [ H.span []
                            [ H.text
                                ((if model.sceneMode == "access" && not model.showBlocked && model.search == "" then
                                    "Connections "

                                  else
                                    "Candidates "
                                 )
                                    ++ String.fromInt (min model.matched (model.offset + 1))
                                    ++ "–"
                                    ++ String.fromInt (min model.matched (model.offset + model.pageLimit))
                                    ++ " of "
                                    ++ String.fromInt model.matched
                                )
                            ]
                        , H.button [ A.disabled (model.offset == 0), Events.onClick (Page (max 0 (model.offset - model.pageLimit))) ] [ H.text "Previous" ]
                        , H.button [ A.disabled (model.nextOffset == Nothing), Events.onClick (Page (Maybe.withDefault 0 model.nextOffset)) ] [ H.text "Next" ]
                        ]

                  else
                    H.span []
                        [ H.text
                            (if model.sceneMode == "overview" && model.search == "" then
                                if model.canvas.width < 600 then
                                    "Select a group to explore its devices"

                                else
                                    "Up to 5 devices per identity · search reaches the whole network"

                             else if model.omitted > 0 then
                                String.fromInt model.omitted ++ " objects beyond this view · narrow the search"

                             else
                                "Select an object to explore"
                            )
                        ]
                ]
            ]
        , inspector model
        ]


inspector : Model -> Html Msg
inspector model =
    H.aside
        [ A.class
            ("network-inspector"
                ++ (if model.inspectorOpen then
                        " is-open"

                    else
                        ""
                   )
            )
        , A.attribute "aria-label" "Network inspector"
        ]
        [ H.div [ A.class "inspector-heading" ]
            [ H.h2 []
                [ H.text
                    (if model.selectedEdge /= Nothing then
                        "Connection"

                     else
                        "Details"
                    )
                ]
            , H.button [ A.type_ "button", A.attribute "aria-label" "Close inspector", Events.onClick CloseInspector ] [ H.text "×" ]
            ]
        , if not model.inspectorOpen then
            H.div [ A.class "network-inspector-hint" ] [ H.div [ A.class "network-hint-glyph", A.attribute "aria-hidden" "true" ] [ H.text "↗" ], H.h3 [] [ H.text "Follow a connection" ], H.p [] [ H.text "Choose a device or identity on the graph. Its connections and policy evidence appear here." ] ]

          else
            H.div [ A.class "network-inspector-content" ]
                [ if model.selectedEdge /= Nothing && List.member model.operation [ "explain", "source" ] then
                    H.div [] [ connectionControls model, detailView model ]

                  else
                    Maybe.map (objectInspector model) model.selected |> Maybe.withDefault (H.text "")
                , H.p [ A.class "network-observation" ] [ H.text "Control-plane state. Online status and policy permission do not prove that an application is reachable." ]
                ]
        ]


objectInspector : Model -> Data.Object -> Html Msg
objectInspector model object =
    H.section []
        [ H.span [ A.class ("network-object-kind " ++ object.kind) ]
            [ H.text
                (if object.kind == "node" then
                    "Device"

                 else
                    object.kind
                )
            ]
        , H.h3 [] [ H.text object.label ]
        , if object.kind == "node" then
            H.p [ A.class "network-online" ]
                [ H.span
                    [ A.class
                        (if object.online == Just True then
                            "status-dot live"

                         else
                            "status-dot"
                        )
                    ]
                    []
                , H.text
                    (if object.expired then
                        "Expired"

                     else if object.online == Just True then
                        "Online"

                     else if object.online == Just False then
                        "Offline"

                     else
                        "Status unknown"
                    )
                ]

          else
            H.text ""
        , if object.memberCount > 0 then
            H.p [] [ H.text (String.fromInt object.memberCount ++ " devices") ]

          else
            H.text ""
        , H.dl []
            [ if not (List.isEmpty object.addresses) then
                H.div [] [ H.dt [] [ H.text "Addresses" ], H.dd [] (List.map (\ip -> H.div [] [ H.code [] [ H.text ip ] ]) object.addresses) ]

              else
                H.text ""
            , if not (List.isEmpty object.tags) then
                H.div [] [ H.dt [] [ H.text "Identity" ], H.dd [] (List.map (\tag -> identityLink model ("tag:" ++ tag) tag) object.tags) ]

              else if object.ownerId /= "" then
                H.div [] [ H.dt [] [ H.text "Owner" ], H.dd [] [ identityLink model object.ownerId object.ownerId ] ]

              else
                H.text ""
            ]
        , H.div [ A.class "network-actions" ]
            (if object.kind == "node" then
                [ button "Explore outgoing access" (AccessFor "outgoing" object), button "Explore incoming access" (AccessFor "incoming" object), button "Show relationships" (TopologyFor object) ]

             else
                [ button "Explore this group" (Explore object) ]
            )
        , if object.kind == "route" then
            H.dl [] [ H.dt [] [ H.text "Advertised" ], H.dd [] [ H.text (bool object.advertised) ], H.dt [] [ H.text "Approved" ], H.dd [] [ H.text (bool object.approved) ], H.dt [] [ H.text "Selected router" ], H.dd [] [ H.text (bool object.selected) ] ]

          else
            H.text ""
        , if object.kind == "service" then
            H.p [] [ H.text (object.protocol ++ " " ++ ports object.firstPort object.lastPort ++ " · " ++ object.provenance) ]

          else
            H.text ""
        , if model.sceneMode == "access" then
            H.p [ A.class "network-tip" ] [ H.text "Select another device or its connection to inspect access. Search can also find a blocked destination." ]

          else
            H.text ""
        ]


identityLink : Model -> String -> String -> Html Msg
identityLink model id label =
    case model.objects |> List.filter (\o -> o.id == id) |> List.head of
        Just object ->
            button object.label (Explore object)

        Nothing ->
            H.span [ A.class "network-tag" ] [ H.text label ]


connectionControls : Model -> Html Msg
connectionControls model =
    let
        name id =
            model.objects |> List.filter (\o -> o.id == id) |> List.head |> Maybe.map .label |> Maybe.withDefault id

        field label key value =
            H.label [] [ H.span [] [ H.text label ], H.input [ A.value value, A.maxlength 512, Events.onInput (Field key) ] [] ]
    in
    H.section [ A.class "network-connection" ]
        [ H.div [ A.class "network-connection-path" ] [ H.strong [] [ H.text (name model.source) ], H.span [ A.attribute "aria-hidden" "true" ] [ H.text "↓" ], H.strong [] [ H.text (name model.destination) ] ]
        , H.p [ A.class "network-transport" ]
            [ H.text
                ((if model.protocol == "6" then
                    "TCP"

                  else if model.protocol == "17" then
                    "UDP"

                  else
                    "IP protocol " ++ model.protocol
                 )
                    ++ (if List.member model.protocol [ "6", "17", "132" ] then
                            " port " ++ model.port_

                        else
                            ""
                       )
                )
            ]
        , H.div [ A.class "network-presets" ] (List.map (\( label, protocol, port_ ) -> pressed label (model.protocol == protocol && model.port_ == port_) (ConnectionTraffic protocol port_)) [ ( "HTTPS", "6", "443" ), ( "HTTP", "6", "80" ), ( "SSH", "6", "22" ), ( "Postgres", "6", "5432" ) ])
        , H.details [ A.class "network-custom-connection" ]
            [ H.summary [] [ H.text "Custom protocol, port or address" ]
            , H.form [ A.class "network-form", Events.onSubmit Explain ]
                [ field "IP protocol" "protocol" model.protocol
                , field "Destination port" "port" model.port_
                , field "Source address (optional)" "sourceIP" model.sourceIP
                , field "Destination node or address" "destination" model.destination
                , field "SSH username (optional)" "sshUser" model.sshUser
                , H.button [ A.type_ "submit", A.disabled model.loading ] [ H.text "Check access" ]
                ]
            ]
        ]


detailView : Model -> Html Msg
detailView model =
    if model.loading then
        H.p [ A.class "network-loading", A.attribute "role" "status" ] [ H.text "Checking policy…" ]

    else
        case model.response of
            Just (Explanation data) ->
                H.section [ A.class "network-explanation" ]
                    [ H.h2 [] [ H.text "Why this connection" ]
                    , H.div [] (List.indexedMap resultView data.results)
                    , H.details [] [ H.summary [] [ H.text "Route and observation details" ], H.p [] [ H.text data.routing ], H.p [] [ H.text data.observation ] ]
                    , Maybe.map (\o -> button ("Explore " ++ o.label) (Explore o)) model.selected |> Maybe.withDefault (H.text "")
                    ]

            Just (SourceChunk data) ->
                H.section [ A.class "network-source" ]
                    [ H.h2 [] [ H.text ("Original source " ++ data.pointer) ]
                    , H.pre [] [ H.text data.text ]
                    , H.p [] [ H.text ("Bytes " ++ String.fromInt data.offset ++ "–" ++ String.fromInt (Maybe.withDefault data.total data.nextOffset) ++ " of " ++ String.fromInt data.total) ]
                    , button "First chunk" (SourcePage data.pointer 0)
                    , H.button [ A.disabled (data.nextOffset == Nothing), Events.onClick (SourcePage data.pointer (Maybe.withDefault 0 data.nextOffset)) ] [ H.text "Next chunk" ]
                    , button "Back to evidence" (EvidencePage model.evidenceResult model.evidenceOffset)
                    ]

            _ ->
                H.text ""


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


resultView : Int -> Data.Result -> Html Msg
resultView index result =
    H.article [ A.class ("network-verdict " ++ result.policy.packet) ]
        [ H.div [ A.class "network-verdict-heading" ]
            [ H.strong [] [ H.text result.policy.packet ]
            , H.span []
                [ H.text
                    (if String.contains ":" result.destinationIP then
                        "IPv6"

                     else
                        "IPv4"
                    )
                ]
            ]
        , H.p [ A.class "network-address-pair" ] [ H.text (result.sourceIP ++ " → " ++ result.destinationIP) ]
        , if result.policy.reason /= "" then
            H.p [] [ H.text result.policy.reason ]

          else
            H.text ""
        , if result.policy.diagnostic /= "" then
            H.p [] [ H.text result.policy.diagnostic ]

          else
            H.text ""
        , H.div [ A.class "network-facts" ]
            [ H.span []
                [ H.text
                    (if result.visible then
                        "Peer visible"

                     else
                        "Peer not visible"
                    )
                ]
            , H.span [] [ H.text ("SSH: " ++ result.policy.ssh) ]
            ]
        , if result.evidenceSelected then
            evidenceView index result.policy

          else
            button "Inspect this address result" (EvidencePage index 0)
        , if List.isEmpty result.routeEvidence then
            H.text ""

          else
            H.details []
                [ H.summary [] [ H.text "Route evidence" ]
                , H.ul [] (List.map (\route -> H.li [] [ H.text (route.label ++ " · advertised " ++ bool route.advertised ++ " · approved " ++ bool route.approved ++ " · selected " ++ bool route.selected ++ " · visible " ++ bool route.sourceVisible) ]) result.routeEvidence)
                ]
        ]


evidenceView : Int -> Data.Policy -> Html Msg
evidenceView index policy =
    H.section [ A.class "network-evidence" ]
        [ if List.isEmpty policy.rules then
            H.text ""

          else
            H.div [] [ H.h4 [] [ H.text "Allowed by policy" ], H.div [] (List.map ruleView policy.rules) ]
        , if List.isEmpty policy.checks then
            H.text ""

          else
            H.details []
                [ H.summary [] [ H.text ("Rule matching checks (" ++ String.fromInt policy.checksTotal ++ ")") ]
                , H.div [] (List.map (\check -> H.section [] [ H.p [] [ H.text check.reason ], ruleView check.rule ]) policy.checks)
                ]
        , if List.isEmpty policy.sshRules then
            H.text ""

          else
            H.details [] [ H.summary [] [ H.text "SSH policy evidence" ], H.div [] (List.map ruleView policy.sshRules) ]
        , if List.isEmpty policy.capabilities then
            H.text ""

          else
            H.details []
                [ H.summary [] [ H.text "Application capabilities" ]
                , H.p [] [ H.text "Capability grants are separate from packet permission." ]
                , H.div [] (List.map (\capability -> H.section [] [ H.strong [] [ H.text capability.name ], H.div [] (List.map ruleView capability.rules) ]) policy.capabilities)
                ]
        , if policy.evidenceNext /= Nothing || policy.evidenceOffset > 0 then
            H.div [ A.class "network-evidence-pages" ]
                [ H.p [] [ H.text ("Showing up to 10 entries per category, from " ++ String.fromInt (policy.evidenceOffset + 1)) ]
                , H.button [ A.type_ "button", A.disabled (policy.evidenceOffset == 0), Events.onClick (EvidencePage index (max 0 (policy.evidenceOffset - 10))) ] [ H.text "Previous evidence" ]
                , H.button [ A.type_ "button", A.disabled (policy.evidenceNext == Nothing), Events.onClick (EvidencePage index (Maybe.withDefault 0 policy.evidenceNext)) ] [ H.text "Next evidence" ]
                ]

          else
            H.text ""
        ]


ruleView : Data.Rule -> Html Msg
ruleView rule =
    let
        witness side value =
            Maybe.map (\m -> H.p [] [ H.text (side ++ ": " ++ m.selector ++ " resolves to " ++ m.address ++ " (" ++ m.ownership ++ ")") ]) value |> Maybe.withDefault (H.text "")
    in
    H.div [ A.class "network-rule" ]
        [ H.div [ A.class "network-rule-location" ] [ H.code [] [ H.text rule.pointer ], H.span [] [ H.text ("line " ++ String.fromInt rule.line) ] ]
        , if String.trim rule.comments == "" then
            H.text ""

          else
            H.p [ A.class "network-rule-comment" ] [ H.text (String.replace "//" "" rule.comments |> String.trim) ]
        , H.details []
            [ H.summary [] [ H.text "View rule source" ]
            , H.pre [] [ H.text rule.excerpt ]
            , witness "Source" rule.sourceMatch
            , witness "Destination" rule.destinationMatch
            , if rule.truncated then
                H.p [] [ H.text "Preview truncated. Open the original source for the complete rule." ]

              else
                H.text ""
            , button "Inspect original source and comments" (SourcePage rule.pointer 0)
            ]
        ]
