port module Main exposing (Msg(..), accept, edgeCurve, edgeOffsets, edgePoints, fit, initial, main, objectFocusTarget, relax, revisionNumber, separate, update, zoomAt)

import Browser
import Browser.Dom as Dom
import Dict exposing (Dict)
import Graph exposing (Edge, Scene, Vertex)
import Html as H exposing (Html)
import Html.Attributes as A
import Html.Events as Events
import Html.Lazy as Lazy
import Json.Decode as D
import Json.Encode as E
import Process
import Set exposing (Set)
import Svg as S
import Svg.Attributes as SA
import Svg.Keyed
import Task


port request : E.Value -> Cmd msg


port receive : (D.Value -> msg) -> Sub msg


type alias Point =
    { x : Float, y : Float }


type alias Camera =
    { x : Float, y : Float, zoom : Float }


type alias Drag =
    { id : Maybe String, start : Point, origin : Point }


type alias Model =
    { scene : Maybe Scene
    , generation : Int
    , perspective : String
    , search : String
    , submitted : String
    , focus : String
    , live : Bool
    , status : String
    , error : String
    , selected : Maybe String
    , inspectorOpen : Bool
    , detail : String
    , detailRequest : Maybe ( String, String )
    , positions : Dict String Point
    , pinned : Set String
    , hidden : Set String
    , hiddenRelations : Set String
    , camera : Camera
    , width : Float
    , height : Float
    , settling : Maybe { remaining : Int, positions : Dict String Point, revision : String }
    , suppressClick : Bool
    , drag : Maybe Drag
    , highlights : Dict String String
    , recent : List String
    , notice : String
    }


type Msg
    = Incoming D.Value
    | Search String
    | Submit
    | Perspective String
    | ToggleLive
    | Refresh
    | Activate String
    | Select String
    | CloseInspector
    | Focus String
    | FocusObjects
    | FocusInspector
    | FocusDone
    | Expand String
    | Overview
    | Category String
    | Relation String
    | Fit
    | SettleLayout
    | SettleStep Int
    | Zoom Float
    | Start (Maybe String) Point
    | StartEdge
    | Move Point
    | End
    | Wheel Point Float
    | Pan Float Float
    | Pin String
    | Mini Point


initial : Model
initial =
    { scene = Nothing, generation = 0, perspective = "core", search = "", submitted = "", focus = "", live = False, status = "Loading", error = "", selected = Nothing, inspectorOpen = False, detail = "", detailRequest = Nothing, positions = Dict.empty, pinned = Set.empty, hidden = Set.empty, hiddenRelations = Set.empty, camera = { x = 60, y = 70, zoom = 1 }, width = 900, height = 650, settling = Nothing, suppressClick = False, drag = Nothing, highlights = Dict.empty, recent = [], notice = "" }


main : Program () Model Msg
main =
    Browser.element { init = \_ -> load initial, update = update, view = view, subscriptions = \_ -> receive Incoming }


send : Model -> String -> List ( String, E.Value ) -> Cmd Msg
send model action fields =
    request (E.object (( "action", E.string action ) :: ( "generation", E.int model.generation ) :: fields))


load : Model -> ( Model, Cmd Msg )
load model =
    let
        next =
            { model | generation = model.generation + 1, status = "Loading", error = "", detail = "", detailRequest = Nothing, highlights = Dict.empty, drag = Nothing, settling = Nothing }
    in
    ( next
    , send next
        "scene"
        [ ( "perspective", E.string next.perspective ), ( "search", E.string next.submitted ), ( "focus", E.string next.focus ), ( "live", E.bool next.live ) ]
    )


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Search value ->
            ( { model | search = value }, Cmd.none )

        Submit ->
            load
                { model
                    | submitted = String.trim model.search
                    , perspective =
                        if String.trim model.search == "" then
                            model.perspective

                        else
                            "world"
                    , focus = ""
                    , scene = Nothing
                    , selected = Nothing
                    , positions = Dict.empty
                }

        Perspective value ->
            load { model | perspective = value, focus = "", scene = Nothing, selected = Nothing, positions = Dict.empty, pinned = Set.empty, hidden = Set.empty, hiddenRelations = Set.empty }

        ToggleLive ->
            if model.live then
                let
                    next =
                        { model | live = False, generation = model.generation + 1, status = "Paused", detail = "Snapshot paused. Select the object again to request details at this revision.", detailRequest = Nothing, highlights = Dict.empty, settling = Nothing }
                in
                ( next, send next "stop" [] )

            else
                load { model | live = True, notice = "Live view converges on current state; intermediate revisions may be skipped." }

        Refresh ->
            load model

        Activate id ->
            if model.suppressClick then
                ( { model | suppressClick = False, settling = Nothing }, Cmd.none )

            else
                inspect { model | selected = Just id, detail = "" }

        Select id ->
            inspect { model | selected = Just id, detail = "" }

        CloseInspector ->
            ( { model | selected = Nothing, inspectorOpen = False, detail = "", detailRequest = Nothing }, Task.attempt (\_ -> FocusDone) (Dom.focus "graph-canvas") )

        Focus id ->
            ( model, Task.attempt (\_ -> FocusDone) (Dom.focus id) )

        FocusObjects ->
            update (Focus (objectFocusTarget model)) model

        FocusInspector ->
            ( { model | inspectorOpen = True }, Task.attempt (\_ -> FocusDone) (Dom.focus "graph-inspector") )

        FocusDone ->
            ( model, Cmd.none )

        Expand id ->
            load { model | perspective = "world", focus = id, search = "", submitted = "", scene = Nothing, selected = Nothing, positions = Dict.empty, hidden = Set.empty, hiddenRelations = Set.empty }

        Overview ->
            load { model | focus = "", submitted = "", search = "", scene = Nothing, selected = Nothing, positions = Dict.empty }

        Category kind ->
            ( { model | hidden = toggle kind model.hidden, settling = Nothing }, Cmd.none )

        Relation kind ->
            ( { model | hiddenRelations = toggle kind model.hiddenRelations, settling = Nothing }, Cmd.none )

        SettleLayout ->
            case model.scene of
                Just scene ->
                    if model.perspective == "world" && model.settling == Nothing then
                        ( { model | settling = Just { remaining = 32, positions = model.positions, revision = scene.revision } }, settleNext model.generation )

                    else
                        ( model, Cmd.none )

                Nothing ->
                    ( model, Cmd.none )

        SettleStep generation ->
            if generation /= model.generation then
                ( model, Cmd.none )

            else
                case ( model.settling, model.scene ) of
                    ( Just work, Just scene ) ->
                        if scene.revision /= work.revision then
                            ( { model | settling = Nothing }, Cmd.none )

                        else
                            let
                                positions =
                                    relax { scene | vertices = visibleVertices model, edges = visibleEdges model } model.pinned work.positions
                            in
                            if work.remaining <= 1 then
                                ( fit { model | positions = separate (visibleVertices model) model.pinned positions, settling = Nothing }, Cmd.none )

                            else
                                ( { model | settling = Just { work | remaining = work.remaining - 1, positions = positions } }, settleNext generation )

                    _ ->
                        ( model, Cmd.none )

        Fit ->
            ( fit model, Cmd.none )

        Zoom factor ->
            ( zoomAt { x = model.width / 2, y = model.height / 2 } factor model, Cmd.none )

        Wheel point delta ->
            ( zoomAt point
                (if delta > 0 then
                    0.9

                 else
                    1.1
                )
                model
            , Cmd.none
            )

        Start id point ->
            let
                origin =
                    case id of
                        Just key ->
                            position model key

                        Nothing ->
                            { x = model.camera.x, y = model.camera.y }
            in
            ( { model | drag = Just { id = id, start = point, origin = origin }, suppressClick = False, settling = Nothing }, Cmd.none )

        StartEdge ->
            ( { model | drag = Nothing, suppressClick = False, settling = Nothing }, Cmd.none )

        Move point ->
            case model.drag of
                Nothing ->
                    ( model, Cmd.none )

                Just drag ->
                    let
                        dx =
                            point.x - drag.start.x

                        dy =
                            point.y - drag.start.y
                    in
                    if not model.suppressClick && dx * dx + dy * dy <= 16 then
                        ( model, Cmd.none )

                    else
                        case drag.id of
                            Just id ->
                                ( { model | suppressClick = True, positions = Dict.insert id { x = drag.origin.x + dx / model.camera.zoom, y = drag.origin.y + dy / model.camera.zoom } model.positions, pinned = Set.insert id model.pinned }, Cmd.none )

                            Nothing ->
                                ( { model | suppressClick = True, camera = { x = drag.origin.x + dx, y = drag.origin.y + dy, zoom = model.camera.zoom } }, Cmd.none )

        End ->
            ( { model | drag = Nothing }, Cmd.none )

        Pan dx dy ->
            ( { model | settling = Nothing, camera = { x = model.camera.x + dx, y = model.camera.y + dy, zoom = model.camera.zoom } }, Cmd.none )

        Pin id ->
            ( { model | pinned = toggle id model.pinned, settling = Nothing }, Cmd.none )

        Mini point ->
            let
                bounds =
                    extent model
            in
            ( { model | settling = Nothing, camera = { x = model.width / 2 - (bounds.left + point.x * bounds.width) * model.camera.zoom, y = model.height / 2 - (bounds.top + point.y * bounds.height) * model.camera.zoom, zoom = model.camera.zoom } }, Cmd.none )

        Incoming value ->
            incoming value model


{-| inspect requests the selection's details at the scene's revision. A
request for the same selection still in flight is left to finish: under
steady churn every patch would otherwise replace it, and no answer would ever
arrive. Its answer, at an older revision, is shown and asks for the current.
A request to another server instance is no such request: that instance's
answer is dropped, so a baseline from a new one supersedes it.
-}
inspect : Model -> ( Model, Cmd Msg )
inspect model =
    case ( model.scene, model.selected ) of
        ( Just scene, Just id ) ->
            if model.detailRequest |> Maybe.map (\( pending, revision ) -> pending == id && instanceOf revision == instanceOf scene.revision) |> Maybe.withDefault False then
                ( model, Cmd.none )

            else if List.any (\v -> v.id == id) scene.vertices then
                ( { model
                    | detailRequest = Just ( id, scene.revision )
                    , detail =
                        if String.isEmpty model.detail then
                            "Loading details…"

                        else
                            model.detail
                  }
                , send model "detail" [ ( "id", E.string id ), ( "revision", E.string scene.revision ) ]
                )

            else
                ( model, Cmd.none )

        _ ->
            ( model, Cmd.none )


{-| detailAnswered shows text, the answer to the selection's request at
revision, and requests the scene's current revision if it moved on since.
Answers for another selection or another server instance are dropped.
-}
detailAnswered : String -> String -> String -> Model -> ( Model, Cmd Msg )
detailAnswered id revision text model =
    let
        current =
            Maybe.map .revision model.scene
    in
    if Just id /= model.selected || Maybe.map instanceOf current /= Just (instanceOf revision) then
        ( model, Cmd.none )

    else if Just revision == current then
        ( { model | detail = text, detailRequest = Nothing }, Cmd.none )

    else
        inspect { model | detail = "Details at an earlier revision; updating.\n" ++ text, detailRequest = Nothing }


incoming : D.Value -> Model -> ( Model, Cmd Msg )
incoming value model =
    let
        envelope =
            D.map2 Tuple.pair (D.field "generation" D.int) (D.field "type" D.string)

        payload decoder =
            D.decodeValue (D.field "data" decoder) value

        failure error =
            ( { model | error = D.errorToString error, status = "Invalid response" }, Cmd.none )
    in
    case D.decodeValue envelope value of
        Err error ->
            failure error

        Ok ( generation, kind ) ->
            if generation /= model.generation && kind /= "geometry" then
                ( model, Cmd.none )

            else
                case kind of
                    "geometry" ->
                        case payload (D.map2 Tuple.pair (D.field "width" D.float) (D.field "height" D.float)) of
                            Ok ( width, height ) ->
                                ( { model | width = width, height = height }, Cmd.none )

                            Err error ->
                                failure error

                    "snapshot" ->
                        case payload Graph.sceneDecoder of
                            Err error ->
                                failure error

                            Ok scene ->
                                let
                                    next =
                                        accept scene model

                                    fitted =
                                        if model.scene == Nothing then
                                            fit next

                                        else
                                            next
                                in
                                inspect
                                    { fitted
                                        | highlights = Dict.empty
                                        , recent = []
                                        , error = ""
                                        , status =
                                            if model.live then
                                                "Live"

                                            else
                                                "Paused"
                                        , notice =
                                            if model.live then
                                                "Fresh baseline. Updates are coalesced; this is not an audit log."

                                            else
                                                "Snapshot paused. Refresh to load the latest state."
                                    }

                    "patch" ->
                        case ( payload Graph.patchDecoder, model.scene ) of
                            ( Ok patch, Just scene ) ->
                                case Graph.applyPatch patch scene of
                                    Err reason ->
                                        load { model | notice = reason }

                                    Ok nextScene ->
                                        let
                                            oldIds =
                                                Set.fromList (List.map .id scene.vertices ++ List.map .id scene.edges)

                                            changes =
                                                List.map
                                                    (\id ->
                                                        ( id
                                                        , if Set.member id oldIds then
                                                            "changed"

                                                          else
                                                            "added"
                                                        )
                                                    )
                                                    (List.map .id patch.vertices ++ List.map .id patch.edges)

                                            relationship edge =
                                                edge.source ++ " " ++ edge.kind ++ " " ++ edge.target

                                            removed =
                                                (List.filter (\v -> List.member v.id patch.removedVertices) scene.vertices |> List.map (\v -> "Removed: " ++ v.label))
                                                    ++ (List.filter (\e -> not (List.any (\current -> current.id == e.id) nextScene.edges)) scene.edges |> List.map (\e -> "Removed relationship: " ++ relationship e))

                                            next =
                                                accept nextScene model

                                            entries =
                                                List.map
                                                    (\v ->
                                                        (if Set.member v.id oldIds then
                                                            "Changed: "

                                                         else
                                                            "Added: "
                                                        )
                                                            ++ v.label
                                                    )
                                                    patch.vertices
                                                    ++ List.map
                                                        (\e ->
                                                            (if Set.member e.id oldIds then
                                                                "Changed relationship: "

                                                             else
                                                                "Added relationship: "
                                                            )
                                                                ++ relationship e
                                                        )
                                                        patch.edges
                                                    ++ removed
                                        in
                                        inspect
                                            { next
                                                | highlights = Dict.fromList changes
                                                , recent = List.take 12 (entries ++ model.recent)
                                                , status = "Live"
                                                , notice =
                                                    if model.selected /= Nothing && next.selected == Nothing then
                                                        "Selected item was removed from this scene."

                                                    else if List.isEmpty entries then
                                                        "Revision advanced; changes may be outside this bounded scene."

                                                    else
                                                        "Latest changes highlighted. Intermediate revisions may be skipped."
                                            }

                            ( Err error, _ ) ->
                                failure error

                            _ ->
                                load model

                    "detail" ->
                        case payload (D.map3 (\revision id data -> ( revision, id, data )) (D.field "revision" D.string) (D.field "id" D.string) (D.field "data" D.value)) of
                            Ok ( revision, id, data ) ->
                                detailAnswered id revision (E.encode 2 data) model

                            Err error ->
                                failure error

                    "detailError" ->
                        case payload (D.map3 (\id revision message -> ( id, revision, message )) (D.field "id" D.string) (D.field "revision" D.string) (D.field "message" D.string)) of
                            Ok ( id, revision, message ) ->
                                detailAnswered id revision message model

                            Err error ->
                                failure error

                    "restore" ->
                        load model

                    "status" ->
                        case payload D.string of
                            Ok status ->
                                ( { model | status = status }, Cmd.none )

                            Err error ->
                                failure error

                    "error" ->
                        case payload D.string of
                            Ok error ->
                                ( { model | error = error, status = "Unavailable" }, Cmd.none )

                            Err error ->
                                failure error

                    _ ->
                        ( model, Cmd.none )


accept : Scene -> Model -> Model
accept scene model =
    let
        retained =
            Dict.filter (\id _ -> List.any (\v -> v.id == id) scene.vertices) model.positions

        layer id visited =
            if Set.member id visited then
                0

            else
                scene.edges
                    |> List.filter (\e -> e.source == id && e.kind == "depends on")
                    |> List.map (\e -> 1 + layer e.target (Set.insert id visited))
                    |> List.maximum
                    |> Maybe.withDefault 0

        group vertex =
            if scene.perspective == "core" then
                layer vertex.id Set.empty

            else
                case vertex.kind of
                    "user" ->
                        0

                    "tag" ->
                        0

                    "node" ->
                        1

                    "route" ->
                        2

                    "filter" ->
                        2

                    _ ->
                        3

        groupWidth column =
            scene.vertices
                |> List.filter (\v -> group v == column)
                |> List.length
                |> (\count -> max 1 ((count + 11) // 12) * 240)

        groupStart column =
            List.range 0 (column - 1)
                |> List.map groupWidth
                |> List.sum
                |> toFloat

        place vertex ( placed, rows ) =
            let
                column =
                    group vertex

                row =
                    Dict.get column rows |> Maybe.withDefault 0

                occupied point =
                    Dict.values placed |> List.any (\p -> abs (p.x - point.x) < 195 && abs (p.y - point.y) < 70)

                available n =
                    let
                        point =
                            if scene.perspective == "core" then
                                { x = toFloat column * 270, y = toFloat n * 104 }

                            else
                                { x = groupStart column + toFloat (n // 12) * 240, y = toFloat (modBy 12 n) * 104 }
                    in
                    if occupied point then
                        available (n + 1)

                    else
                        point
            in
            if Dict.member vertex.id placed then
                ( placed, rows )

            else
                ( Dict.insert vertex.id (available row) placed, Dict.insert column (row + 1) rows )

        positions =
            List.sortBy .id scene.vertices |> List.foldl place ( retained, Dict.empty ) |> Tuple.first
    in
    { model
        | scene = Just scene
        , positions = positions
        , selected = Graph.selection scene model.selected
        , pinned = Set.filter (\id -> Dict.member id positions) model.pinned
        , settling =
            case ( model.settling, model.scene ) of
                ( Just work, Just previous ) ->
                    if Dict.size retained == Dict.size model.positions && Dict.size retained == List.length scene.vertices && List.sortBy .id previous.edges == List.sortBy .id scene.edges then
                        Just { work | revision = scene.revision }

                    else
                        Nothing

                _ ->
                    Nothing
    }


settleNext : Int -> Cmd Msg
settleNext generation =
    Process.sleep 0 |> Task.perform (\_ -> SettleStep generation)


separate : List Vertex -> Set String -> Dict String Point -> Dict String Point
separate vertices pinned positions =
    let
        visible =
            Set.fromList (List.map .id vertices)

        points =
            Dict.toList positions |> List.filter (\( id, _ ) -> Set.member id visible)

        fixed =
            points |> List.filter (\( id, _ ) -> Set.member id pinned) |> List.map Tuple.second |> List.sortBy .y

        place ( id, point ) ( result, occupied ) =
            if Set.member id pinned then
                ( result, occupied )

            else
                let
                    -- Sorted obstacles make this single downward sweep collision-free.
                    clear other candidate =
                        if abs (candidate.x - other.x) < 210 && abs (candidate.y - other.y) < 78 then
                            { candidate | y = other.y + 78 }

                        else
                            candidate

                    next =
                        List.foldl clear point occupied
                in
                ( Dict.insert id next result, List.sortBy .y (next :: occupied) )
    in
    points
        |> List.sortBy (\( id, point ) -> ( point.y, point.x, id ))
        |> List.foldl place ( positions, fixed )
        |> Tuple.first


relax : Scene -> Set String -> Dict String Point -> Dict String Point
relax scene pinned positions =
    let
        visible =
            Set.fromList (List.map .id scene.vertices)

        points =
            Dict.toList positions |> List.filter (\( id, _ ) -> Set.member id visible)

        neighbors =
            List.foldl
                (\edge graph ->
                    graph
                        |> Dict.update edge.source (\ids -> Just (edge.target :: Maybe.withDefault [] ids))
                        |> Dict.update edge.target (\ids -> Just (edge.source :: Maybe.withDefault [] ids))
                )
                Dict.empty
                scene.edges

        move id point =
            if Set.member id pinned || not (Set.member id visible) then
                point

            else
                let
                    repel ( otherId, other ) force =
                        if otherId == id then
                            force

                        else
                            let
                                dx =
                                    if other == point then
                                        if id < otherId then
                                            -1

                                        else
                                            1

                                    else
                                        point.x - other.x

                                dy =
                                    if other == point then
                                        if id < otherId then
                                            -1

                                        else
                                            1

                                    else
                                        point.y - other.y

                                distance =
                                    max 1 (sqrt (dx * dx + dy * dy))

                                strength =
                                    min 18 (18000 / (distance * distance))

                                overlap =
                                    abs dx < 220 && abs dy < 90

                                horizontal =
                                    abs dx / 220 > abs dy / 90

                                pushX =
                                    if overlap && horizontal then
                                        if dx < 0 then
                                            -18

                                        else
                                            18

                                    else
                                        0

                                pushY =
                                    if overlap && not horizontal then
                                        if dy < 0 then
                                            -18

                                        else
                                            18

                                    else
                                        0
                            in
                            { x = force.x + dx / distance * strength + pushX, y = force.y + dy / distance * strength + pushY }

                    attract otherId force =
                        case Dict.get otherId positions of
                            Nothing ->
                                force

                            Just other ->
                                let
                                    dx =
                                        other.x - point.x

                                    dy =
                                        other.y - point.y

                                    distance =
                                        max 1 (sqrt (dx * dx + dy * dy))

                                    strength =
                                        clamp -8 18 ((distance - 270) * 0.04)
                                in
                                { x = force.x + dx / distance * strength, y = force.y + dy / distance * strength }

                    repulsion =
                        List.foldl repel { x = 0, y = 0 } points

                    totalForce =
                        List.foldl attract repulsion (Dict.get id neighbors |> Maybe.withDefault [])
                in
                { x = point.x + clamp -24 24 totalForce.x, y = point.y + clamp -24 24 totalForce.y }
    in
    Dict.map move positions


toggle : comparable -> Set comparable -> Set comparable
toggle key values =
    if Set.member key values then
        Set.remove key values

    else
        Set.insert key values


position : Model -> String -> Point
position model id =
    Dict.get id model.positions |> Maybe.withDefault { x = 0, y = 0 }


extent : Model -> { left : Float, top : Float, width : Float, height : Float }
extent model =
    let
        points =
            visibleVertices model |> List.map (\v -> position model v.id)

        left =
            List.minimum (List.map .x points) |> Maybe.withDefault 0

        top =
            List.minimum (List.map .y points) |> Maybe.withDefault 0

        right =
            List.maximum (List.map .x points) |> Maybe.withDefault 400

        bottom =
            List.maximum (List.map .y points) |> Maybe.withDefault 300
    in
    { left = left - 30, top = top - 30, width = right - left + 250, height = bottom - top + 130 }


fit : Model -> Model
fit model =
    let
        bounds =
            extent model

        scale =
            clamp 0.08 1.3 (min ((model.width - 60) / bounds.width) ((model.height - 60) / bounds.height))
    in
    { model | settling = Nothing, camera = { x = (model.width - bounds.width * scale) / 2 - bounds.left * scale, y = (model.height - bounds.height * scale) / 2 - bounds.top * scale, zoom = scale } }


zoomAt : Point -> Float -> Model -> Model
zoomAt point factor model =
    let
        camera =
            model.camera

        scale =
            clamp 0.08 3 (camera.zoom * factor)

        ratio =
            scale / camera.zoom
    in
    { model | settling = Nothing, camera = { x = point.x - (point.x - camera.x) * ratio, y = point.y - (point.y - camera.y) * ratio, zoom = scale } }


visibleVertices : Model -> List Vertex
visibleVertices model =
    Maybe.map .vertices model.scene |> Maybe.withDefault [] |> List.filter (\v -> not (Set.member v.kind model.hidden))


visibleEdges : Model -> List Edge
visibleEdges model =
    let
        ids =
            Set.fromList (List.map .id (visibleVertices model))
    in
    Maybe.map .edges model.scene |> Maybe.withDefault [] |> List.filter (\e -> Set.member e.source ids && Set.member e.target ids && not (Set.member e.kind model.hiddenRelations))


number : Float -> String
number =
    String.fromFloat


{-| instanceOf is the server instance a revision belongs to: revisions
compare only within one.
-}
instanceOf : String -> String
instanceOf revision =
    String.left (String.length revision - String.length (revisionNumber revision)) revision


revisionNumber : String -> String
revisionNumber revision =
    String.split ":" revision |> List.reverse |> List.head |> Maybe.withDefault revision


objectFocusTarget : Model -> String
objectFocusTarget model =
    visibleVertices model |> List.head |> Maybe.map (\vertex -> "graph-object-" ++ vertex.id) |> Maybe.withDefault "graph-canvas"


button : String -> Msg -> Html Msg
button label msg =
    H.button [ A.type_ "button", Events.onClick msg ] [ H.text label ]


view : Model -> Html Msg
view model =
    H.div [ A.class "app" ]
        [ H.header [ A.class "toolbar" ]
            [ H.a [ A.class "brand", A.href "/debug/" ] [ H.img [ A.class "brand-logo", A.attribute "data-headscale-logo" "", A.alt "Headscale", A.width 98, A.height 44 ] [], H.span [ A.class "brand-section" ] [ H.text "Graph" ] ]
            , H.form [ A.class "search", Events.onSubmit Submit ] [ H.input [ A.type_ "search", A.placeholder "Find a device, address or object…", A.attribute "aria-label" "Search graph", A.value model.search, Events.onInput Search ] [], H.button [ A.type_ "submit" ] [ H.text "Search" ] ]
            , H.div [ A.class "connection", A.attribute "role" "status" ]
                [ H.span
                    [ A.class
                        (if model.status == "Live" then
                            "status-dot live"

                         else
                            "status-dot"
                        )
                    ]
                    []
                , H.text model.status
                ]
            , H.button [ A.type_ "button", A.class "live-toggle", A.attribute "aria-pressed" (bool model.live), Events.onClick ToggleLive ]
                [ H.text
                    (if model.live then
                        "Pause live"

                     else
                        "Go live"
                    )
                ]
            , button "Refresh" Refresh
            ]
        , H.div [ A.class "workspace" ]
            [ sidebar model
            , H.main_ [ A.class "scene-panel" ]
                [ H.div [ A.class "scene-heading" ]
                    [ H.div []
                        [ H.h1 []
                            [ H.text
                                (if model.perspective == "core" then
                                    "Graph internals"

                                 else
                                    "Tailnet relationships"
                                )
                            ]
                        , H.p []
                            [ H.text
                                (if model.perspective == "core" then
                                    "Inputs, derived values and their live dependencies"

                                 else
                                    "Devices, ownership and the state that connects them"
                                )
                            ]
                        ]
                    , H.span [ A.class "revision", A.title (Maybe.map .timestamp model.scene |> Maybe.withDefault "") ] [ H.text ("Revision " ++ (Maybe.map (.revision >> revisionNumber) model.scene |> Maybe.withDefault "—")) ]
                    ]
                , if model.error /= "" then
                    H.div [ A.class "banner error", A.attribute "role" "alert" ] [ H.text model.error, button "Retry" Refresh ]

                  else
                    H.text ""
                , case model.scene of
                    Just scene ->
                        if scene.policyError /= "" then
                            H.div [ A.class "banner error", A.attribute "role" "alert" ] [ H.text ("Policy compilation: " ++ scene.policyError) ]

                        else
                            H.text ""

                    Nothing ->
                        H.text ""
                , H.div [ A.class "canvas-wrap" ]
                    [ H.nav [ A.class "graph-skips", A.attribute "aria-label" "Skip graph navigation" ]
                        [ button "Skip to objects" FocusObjects
                        , button "Skip to inspector" FocusInspector
                        ]
                    , canvas model
                    , if List.isEmpty (visibleVertices model) then
                        H.div [ A.class "empty" ]
                            [ H.h2 []
                                [ H.text
                                    (if model.status == "Loading" then
                                        "Loading graph…"

                                     else
                                        "No visible objects"
                                    )
                                ]
                            , H.p [] [ H.text "Search for a different name or address, or enable categories in the legend." ]
                            , button "Clear search and focus" Overview
                            ]

                      else
                        H.text ""
                    , H.div [ A.class "canvas-help" ] [ H.text "Drag background to pan. Drag an object to pin. Scroll to zoom." ]
                    , minimap model
                    , H.div [ A.class "camera-controls", A.attribute "aria-label" "Graph camera" ] [ button "−" (Zoom 0.8), H.output [] [ H.text (String.fromInt (round (model.camera.zoom * 100)) ++ "%") ], button "+" (Zoom 1.25), button "Fit" Fit ]
                    ]
                , footer model
                ]
            , inspector model
            ]
        ]


bool : Bool -> String
bool value =
    if value then
        "true"

    else
        "false"


sidebar : Model -> Html Msg
sidebar model =
    let
        vertices =
            Maybe.map .vertices model.scene |> Maybe.withDefault []

        categories =
            [ "input", "derived", "node", "user", "tag", "route", "filter", "derp", "dns" ] |> List.filter (\kind -> List.any (\v -> v.kind == kind) vertices)

        relations =
            Maybe.map .edges model.scene |> Maybe.withDefault [] |> List.map .kind |> Set.fromList |> Set.toList
    in
    H.aside [ A.class "sidebar", A.attribute "aria-label" "Graph navigation" ]
        [ H.div [ A.class "perspectives" ]
            (List.map
                (\p ->
                    H.button
                        [ A.type_ "button"
                        , A.class
                            (if model.perspective == p then
                                "active"

                             else
                                ""
                            )
                        , A.attribute "aria-pressed" (bool (model.perspective == p))
                        , Events.onClick (Perspective p)
                        ]
                        [ H.text
                            (if p == "core" then
                                "Core"

                             else
                                "World"
                            )
                        ]
                )
                [ "core", "world" ]
            )
        , if model.perspective == "world" then
            H.div [ A.class "layout-action" ]
                [ H.button [ A.type_ "button", A.disabled (model.settling /= Nothing || model.scene == Nothing), Events.onClick SettleLayout ]
                    [ H.text
                        (if model.settling /= Nothing then
                            "Settling…"

                         else
                            "Settle layout"
                        )
                    ]
                , H.p [] [ H.text "Settle visible objects once. Pinned objects stay fixed." ]
                ]

          else
            H.text ""
        , H.h2 [] [ H.text "Categories" ]
        , H.div [ A.class "legend" ] (List.map (\kind -> H.label [] [ H.input [ A.type_ "checkbox", A.checked (not (Set.member kind model.hidden)), Events.onCheck (\_ -> Category kind) ] [], H.span [ A.class ("swatch " ++ kind) ] [], H.span [] [ H.text (kindLabel kind) ], H.small [] [ H.text (String.fromInt (List.length (List.filter (\v -> v.kind == kind) vertices))) ] ]) categories)
        , H.h2 [] [ H.text "Relationships" ]
        , H.div [ A.class "relation-legend" ] (List.map (\kind -> H.label [] [ H.input [ A.type_ "checkbox", A.checked (not (Set.member kind model.hiddenRelations)), Events.onCheck (\_ -> Relation kind) ] [], H.span [] [ H.text kind ] ]) relations)
        , if model.focus /= "" || model.submitted /= "" then
            H.div [ A.class "scope" ]
                [ H.h2 [] [ H.text "Current scope" ]
                , H.p []
                    [ H.text
                        (if model.focus /= "" then
                            model.focus

                         else
                            model.submitted
                        )
                    ]
                , button "Back to overview" Overview
                ]

          else
            H.text ""
        , H.div [ A.class "sidebar-note" ] [ H.strong [] [ H.text "A window into current state" ], H.p [] [ H.text ("Scenes are bounded to " ++ String.fromInt Graph.vertexLimit ++ " objects and " ++ String.fromInt Graph.edgeLimit ++ " relationships. Search or focus to explore further.") ], H.p [] [ H.text "Not recommended for large installations. Peer visibility does not imply traffic permission." ] ]
        ]


kindLabel : String -> String
kindLabel kind =
    case kind of
        "input" ->
            "Inputs"

        "derived" ->
            "Derived values"

        "node" ->
            "Devices"

        "user" ->
            "Users"

        "tag" ->
            "Tags"

        "route" ->
            "Routes"

        "filter" ->
            "Packet filters"

        "derp" ->
            "DERP"

        "dns" ->
            "DNS"

        _ ->
            kind


pointDecoder : D.Decoder Point
pointDecoder =
    D.map2 Point (D.field "clientX" D.float) (D.field "clientY" D.float)


canvas : Model -> Html Msg
canvas model =
    S.svg
        [ SA.id "graph-canvas"
        , SA.class "graph-canvas"
        , SA.width "100%"
        , SA.height "100%"
        , SA.viewBox ("0 0 " ++ number model.width ++ " " ++ number model.height)
        , A.attribute "tabindex" "0"
        , A.attribute "role" "group"
        , A.attribute "aria-label" "Interactive graph. Arrow keys pan, plus and minus zoom, zero fits. O jumps to objects, I to the inspector. Enter selects."
        , Events.on "pointerdown" (D.map (Start Nothing) pointDecoder)
        , Events.on "pointermove" (D.map Move pointDecoder)
        , Events.on "pointerup" (D.succeed End)
        , Events.on "pointercancel" (D.succeed End)
        , Events.preventDefaultOn "wheel" (D.map2 (\point delta -> ( Wheel point delta, True )) (D.field "graphPoint" (D.map2 Point (D.field "x" D.float) (D.field "y" D.float))) (D.field "deltaY" D.float))
        , Events.preventDefaultOn "keydown" (D.field "key" D.string |> D.andThen cameraKey)
        ]
        [ S.defs []
            (List.map
                (\( id, color ) ->
                    S.marker
                        [ SA.id id
                        , SA.viewBox "0 0 10 10"
                        , SA.refX "10"
                        , SA.refY "5"
                        , SA.markerUnits "userSpaceOnUse"
                        , SA.markerWidth (number (10 / model.camera.zoom))
                        , SA.markerHeight (number (10 / model.camera.zoom))
                        , SA.orient "auto"
                        ]
                        [ S.path [ SA.d "M 0 0 L 10 5 L 0 10 L 2 5 z", SA.fill color ] [] ]
                )
                [ ( "arrow", "#b75179" ), ( "arrow-active", "#8a3153" ), ( "arrow-change", "#258663" ) ]
            )
        , Lazy.lazy8 sceneContent model.scene model.positions model.camera model.selected model.hidden model.hiddenRelations model.highlights model.pinned
        ]


sceneContent scene positions camera selected hidden hiddenRelations highlights pinned =
    let
        model =
            { initial | scene = scene, positions = positions, camera = camera, selected = selected, hidden = hidden, hiddenRelations = hiddenRelations, highlights = highlights, pinned = pinned }

        bounds =
            extent model

        offsets =
            Maybe.map (.edges >> edgeOffsets) scene |> Maybe.withDefault Dict.empty
    in
    Svg.Keyed.node "g"
        [ SA.transform ("translate(" ++ number model.camera.x ++ "," ++ number model.camera.y ++ ") scale(" ++ number model.camera.zoom ++ ")") ]
        ([ ( "scene-background", S.rect [ SA.x (number bounds.left), SA.y (number bounds.top), SA.width (number bounds.width), SA.height (number bounds.height), SA.rx "18", SA.class "scene-background" ] [] ) ] ++ List.map (\edge -> ( "edge-" ++ edge.id, edgeView model (Dict.get edge.id offsets |> Maybe.withDefault 0) edge )) (visibleEdges model) ++ List.map (\vertex -> ( "vertex-" ++ vertex.id, vertexView model vertex )) (visibleVertices model))


cameraKey : String -> D.Decoder ( Msg, Bool )
cameraKey key =
    case key of
        "ArrowLeft" ->
            D.succeed ( Pan 40 0, True )

        "ArrowRight" ->
            D.succeed ( Pan -40 0, True )

        "ArrowUp" ->
            D.succeed ( Pan 0 40, True )

        "ArrowDown" ->
            D.succeed ( Pan 0 -40, True )

        "+" ->
            D.succeed ( Zoom 1.25, True )

        "=" ->
            D.succeed ( Zoom 1.25, True )

        "-" ->
            D.succeed ( Zoom 0.8, True )

        "0" ->
            D.succeed ( Fit, True )

        "o" ->
            D.succeed ( FocusObjects, True )

        "i" ->
            D.succeed ( FocusInspector, True )

        _ ->
            D.fail "Not a camera key"


selectKey : String -> D.Decoder ( Msg, Bool )
selectKey id =
    D.field "key" D.string
        |> D.andThen
            (\key ->
                if key == "Enter" || key == " " then
                    D.succeed ( Select id, True )

                else
                    D.fail "Not an activation key"
            )


vertexView : Model -> Vertex -> S.Svg Msg
vertexView model vertex =
    let
        point =
            position model vertex.id

        selected =
            model.selected == Just vertex.id

        marker =
            Dict.get vertex.id model.highlights |> Maybe.withDefault ""

        label =
            if String.length vertex.label > 23 then
                String.left 22 vertex.label ++ "…"

            else
                vertex.label
    in
    S.g
        [ SA.class
            ("vertex "
                ++ vertex.kind
                ++ (if selected then
                        " selected"

                    else
                        ""
                   )
                ++ (if marker /= "" then
                        " highlighted"

                    else
                        ""
                   )
            )
        , SA.transform ("translate(" ++ number point.x ++ "," ++ number point.y ++ ")")
        , SA.id ("graph-object-" ++ vertex.id)
        , A.attribute "tabindex" "0"
        , A.attribute "role" "button"
        , A.attribute "aria-label" (vertex.label ++ ", " ++ vertex.kind ++ ". " ++ vertex.summary)
        , A.attribute "aria-pressed" (bool selected)
        , Events.stopPropagationOn "pointerdown" (D.map (\p -> ( Start (Just vertex.id) p, True )) pointDecoder)
        , Events.onClick (Activate vertex.id)
        , Events.preventDefaultOn "keydown" (selectKey vertex.id)
        ]
        [ S.title [] [ S.text (vertex.label ++ "\n" ++ vertex.summary ++ "\nChanged at " ++ vertex.changedAt) ]
        , S.rect
            [ SA.class "node-body"
            , SA.width "198"
            , SA.height "66"
            , SA.rx
                (if vertex.kind == "input" then
                    "4"

                 else
                    "13"
                )
            ]
            []
        , case vertex.kind of
            "node" ->
                S.g [ SA.class "device-glyph" ]
                    [ S.rect [ SA.x "11", SA.y "8", SA.width "18", SA.height "13", SA.rx "2", SA.class "glyph-frame" ] []
                    , S.rect [ SA.x "14", SA.y "11", SA.width "12", SA.height "7", SA.rx "1", SA.class "glyph-pink" ] []
                    , S.path [ SA.d "M9 23H31L29 26H11Z", SA.class "glyph-frame" ] []
                    ]

            "derived" ->
                S.path [ SA.class "node-symbol", SA.d "M 14 17 L 20 11 L 26 17 L 20 23 Z" ] []

            "input" ->
                S.rect [ SA.class "node-symbol", SA.x "15", SA.y "12", SA.width "10", SA.height "10", SA.rx "1" ] []

            "tag" ->
                S.path [ SA.class "node-symbol", SA.d "M14 12H22L27 17L22 22H14Z" ] []

            "route" ->
                S.path [ SA.class "node-symbol", SA.d "M13 14H21V10L28 17L21 24V20H13Z" ] []

            "filter" ->
                S.path [ SA.class "node-symbol", SA.d "M13 11H27L22 18V23H18V18Z" ] []

            "derp" ->
                S.g []
                    [ S.rect [ SA.class "glyph-frame", SA.x "13", SA.y "10", SA.width "15", SA.height "6", SA.rx "1" ] []
                    , S.rect [ SA.class "glyph-frame", SA.x "13", SA.y "18", SA.width "15", SA.height "6", SA.rx "1" ] []
                    , S.circle [ SA.class "glyph-pink", SA.cx "16", SA.cy "13", SA.r "1.5" ] []
                    , S.circle [ SA.class "glyph-pink", SA.cx "16", SA.cy "21", SA.r "1.5" ] []
                    ]

            "dns" ->
                S.path [ SA.class "node-symbol", SA.d "M14 11H19V16H14Z M21 11H26V16H21Z M14 18H19V23H14Z M21 18H26V23H21Z" ] []

            _ ->
                S.circle [ SA.class "node-symbol", SA.cx "20", SA.cy "17", SA.r "5" ] []
        , S.text_ [ SA.class "node-kind", SA.x "34", SA.y "21" ]
            [ S.text
                (vertex.kind
                    ++ (if Set.member vertex.id model.pinned then
                            " / pinned"

                        else
                            ""
                       )
                )
            ]
        , if model.camera.zoom >= 0.38 || selected then
            S.text_ [ SA.class "node-label", SA.x "14", SA.y "47" ] [ S.text label ]

          else
            S.text ""
        , if marker /= "" then
            S.text_ [ SA.class "change-label", SA.x "198", SA.y "-8", SA.textAnchor "end" ] [ S.text marker ]

          else
            S.text ""
        ]


edgePoints : Point -> Point -> { source : Point, target : Point, horizontal : Bool, direction : Float }
edgePoints source target =
    let
        dx =
            target.x - source.x

        dy =
            target.y - source.y

        horizontal =
            abs dx >= abs dy

        forward =
            if horizontal then
                dx >= 0

            else
                dy >= 0
    in
    if horizontal then
        { source =
            { x =
                source.x
                    + (if forward then
                        198

                       else
                        0
                      )
            , y = source.y + 33
            }
        , target =
            { x =
                target.x
                    + (if forward then
                        0

                       else
                        198
                      )
            , y = target.y + 33
            }
        , horizontal = True
        , direction =
            if forward then
                1

            else
                -1
        }

    else
        { source =
            { x = source.x + 99
            , y =
                source.y
                    + (if forward then
                        66

                       else
                        0
                      )
            }
        , target =
            { x = target.x + 99
            , y =
                target.y
                    + (if forward then
                        0

                       else
                        66
                      )
            }
        , horizontal = False
        , direction =
            if forward then
                1

            else
                -1
        }


edgeOffsets : List Edge -> Dict String Float
edgeOffsets edges =
    -- Include hidden relationships so filtering does not move the remaining curves.
    edges
        |> List.foldl
            (\edge groups ->
                Dict.update ( min edge.source edge.target, max edge.source edge.target )
                    (\group -> Just (edge :: Maybe.withDefault [] group))
                    groups
            )
            Dict.empty
        |> Dict.values
        |> List.concatMap
            (\group ->
                let
                    center =
                        toFloat (List.length group - 1) / 2
                in
                List.sortBy .id group |> List.indexedMap (\index edge -> ( edge.id, (toFloat index - center) * 36 ))
            )
        |> Dict.fromList


edgeCurve : Float -> Point -> Point -> { source : Point, target : Point, control1 : Point, control2 : Point, path : String, label : Point }
edgeCurve offset source target =
    let
        points =
            edgePoints source target

        bend =
            if points.horizontal then
                max 30 (abs (points.target.x - points.source.x) / 2)

            else
                max 30 (abs (points.target.y - points.source.y) / 2)

        control anchor direction =
            if points.horizontal then
                { anchor | x = anchor.x + direction * bend, y = anchor.y + offset }

            else
                { anchor | x = anchor.x + offset, y = anchor.y + direction * bend }

        shape =
            if abs (source.x - target.x) < 198 && abs (source.y - target.y) < 66 then
                let
                    top =
                        min source.y target.y - 80 - abs offset

                    a =
                        { x = source.x + 49, y = source.y }

                    b =
                        { x = target.x + 149, y = target.y }
                in
                -- Route overlapping cards above their borders rather than through their interiors.
                { source = a, target = b, control1 = { x = a.x - 40 + offset, y = top }, control2 = { x = b.x + 40 + offset, y = top } }

            else
                { source = points.source, target = points.target, control1 = control points.source points.direction, control2 = control points.target -points.direction }

        coordinate point =
            number point.x ++ " " ++ number point.y
    in
    { source = shape.source
    , target = shape.target
    , control1 = shape.control1
    , control2 = shape.control2
    , path = "M " ++ coordinate shape.source ++ " C " ++ coordinate shape.control1 ++ ", " ++ coordinate shape.control2 ++ ", " ++ coordinate shape.target
    , label = { x = (shape.source.x + 3 * shape.control1.x + 3 * shape.control2.x + shape.target.x) / 8, y = (shape.source.y + 3 * shape.control1.y + 3 * shape.control2.y + shape.target.y) / 8 }
    }


edgeView : Model -> Float -> Edge -> S.Svg Msg
edgeView model offset edge =
    let
        curve =
            edgeCurve offset (position model edge.source) (position model edge.target)

        label id =
            Maybe.map .vertices model.scene |> Maybe.withDefault [] |> List.filter (\v -> v.id == id) |> List.head |> Maybe.map .label |> Maybe.withDefault id

        selected =
            model.selected == Just edge.id
    in
    S.g
        [ SA.class
            ("edge"
                ++ (if Dict.member edge.id model.highlights then
                        " highlighted"

                    else
                        ""
                   )
                ++ (if selected then
                        " selected"

                    else
                        ""
                   )
            )
        , A.attribute "tabindex" "0"
        , A.attribute "role" "button"
        , A.attribute "aria-label" (edge.source ++ " " ++ edge.kind ++ " " ++ edge.target)
        , Events.onClick (Activate edge.id)
        , Events.stopPropagationOn "pointerdown" (D.succeed ( StartEdge, True ))
        , Events.preventDefaultOn "keydown" (selectKey edge.id)
        ]
        [ S.title [] [ S.text (edge.source ++ " → " ++ edge.kind ++ " → " ++ edge.target) ]
        , S.path [ SA.class "edge-hit", SA.d curve.path, A.attribute "vector-effect" "non-scaling-stroke" ] []
        , S.path
            [ SA.class "edge-line"
            , SA.d curve.path
            , A.attribute "vector-effect" "non-scaling-stroke"
            , SA.markerEnd "url(#arrow)"
            , SA.strokeDasharray
                (if edge.kind == "visible to" then
                    "5 5"

                 else
                    "none"
                )
            ]
            []
        , S.text_
            [ SA.class "edge-label"
            , SA.x (number curve.label.x)
            , SA.y (number (curve.label.y - 12 / model.camera.zoom))
            , SA.textAnchor "middle"
            , SA.style ("font-size:" ++ number (12 / model.camera.zoom) ++ "px;stroke-width:" ++ number (5 / model.camera.zoom) ++ "px")
            ]
            [ S.text (label edge.source ++ " → " ++ edge.kind ++ " → " ++ label edge.target) ]
        ]


minimap : Model -> Html Msg
minimap model =
    Lazy.lazy7 minimapView model.scene model.positions model.camera model.hidden model.selected model.width model.height


minimapView scene positions camera hidden selected width height =
    minimapContent { initial | scene = scene, positions = positions, camera = camera, hidden = hidden, selected = selected, width = width, height = height }


minimapContent : Model -> Html Msg
minimapContent model =
    let
        bounds =
            extent model

        camera =
            model.camera
    in
    H.div [ A.class "minimap" ]
        [ H.span [] [ H.text "Scene overview" ]
        , S.svg [ SA.id "graph-minimap", SA.viewBox (String.join " " (List.map number [ bounds.left, bounds.top, bounds.width, bounds.height ])), SA.preserveAspectRatio "none", A.attribute "role" "img", A.attribute "aria-label" "Scene overview. Click to recenter.", Events.on "click" (D.field "miniPoint" (D.map2 Point (D.field "x" D.float) (D.field "y" D.float)) |> D.map Mini) ]
            (List.map
                (\v ->
                    let
                        p =
                            position model v.id
                    in
                    S.rect
                        [ SA.x (number p.x)
                        , SA.y (number p.y)
                        , SA.width "198"
                        , SA.height "66"
                        , SA.fill
                            (if model.selected == Just v.id then
                                "#8a3153"

                             else
                                "#bababa"
                            )
                        , SA.rx "10"
                        ]
                        []
                )
                (visibleVertices model)
                ++ [ S.rect [ SA.class "minimap-viewport", SA.x (number (-camera.x / camera.zoom)), SA.y (number (-camera.y / camera.zoom)), SA.width (number (model.width / camera.zoom)), SA.height (number (model.height / camera.zoom)) ] [] ]
            )
        ]


footer : Model -> Html Msg
footer model =
    H.footer [ A.class "scene-footer" ]
        [ case model.scene of
            Nothing ->
                H.span [] [ H.text "Waiting for a snapshot" ]

            Just scene ->
                H.span []
                    [ H.strong [] [ H.text (String.fromInt scene.shownNodes ++ " of " ++ String.fromInt scene.totalNodes ++ " devices") ]
                    , H.text (" / " ++ String.fromInt scene.matchedNodes ++ " match / " ++ String.fromInt (List.length (visibleVertices model)) ++ " objects / " ++ String.fromInt (List.length (visibleEdges model)) ++ " relations")
                    , if scene.truncated then
                        H.strong [ A.class "partial" ] [ H.text "Partial scene — narrow search or focus" ]

                      else
                        H.text ""
                    ]
        , H.p [ A.attribute "role" "status" ] [ H.text model.notice ]
        ]


inspector : Model -> Html Msg
inspector model =
    let
        sceneVertices =
            Maybe.map .vertices model.scene |> Maybe.withDefault []

        sceneEdges =
            Maybe.map .edges model.scene |> Maybe.withDefault []

        vertex =
            List.filter (\v -> Just v.id == model.selected) sceneVertices |> List.head

        edge =
            List.filter (\e -> Just e.id == model.selected) sceneEdges |> List.head

        label id =
            List.filter (\v -> v.id == id) sceneVertices |> List.head |> Maybe.map .label |> Maybe.withDefault id

        related id =
            sceneEdges |> List.filter (\e -> e.source == id || e.target == id)
    in
    H.aside
        [ A.class
            ("inspector"
                ++ (if model.selected /= Nothing || model.inspectorOpen then
                        " is-open"

                    else
                        ""
                   )
            )
        , A.attribute "aria-label" "Selection inspector"
        , A.id "graph-inspector"
        , A.tabindex -1
        , Events.preventDefaultOn "keydown"
            (D.field "key" D.string
                |> D.andThen
                    (\key ->
                        if key == "Escape" then
                            D.succeed ( CloseInspector, True )

                        else
                            D.fail "Not an inspector key"
                    )
            )
        ]
        ([ H.div [ A.class "inspector-heading" ]
            [ H.h2 [] [ H.text "Inspector" ]
            , if model.selected /= Nothing || model.inspectorOpen then
                button "Close" CloseInspector

              else
                H.text ""
            ]
         ]
            ++ (case ( vertex, edge ) of
                    ( Just v, _ ) ->
                        [ H.span [ A.class ("kind-badge " ++ v.kind) ] [ H.text v.kind ]
                        , H.h3 [] [ H.text v.label ]
                        , H.code [ A.class "object-id" ] [ H.text v.id ]
                        , H.p [] [ H.text v.summary ]
                        , H.div [ A.class "inspector-actions" ]
                            [ button "Explore relationships" (Expand v.id)
                            , button
                                (if Set.member v.id model.pinned then
                                    "Unpin"

                                 else
                                    "Pin position"
                                )
                                (Pin v.id)
                            ]
                        , H.h4 [] [ H.text "Properties" ]
                        , H.dl [] (List.concatMap (\( key, value ) -> [ H.dt [] [ H.text key ], H.dd [] [ H.text value ] ]) (( "Changed at", v.changedAt ) :: Dict.toList v.properties))
                        , H.h4 [] [ H.text "Related objects" ]
                        , H.ul [ A.class "related" ]
                            (List.map
                                (\e ->
                                    H.li []
                                        [ H.span []
                                            [ H.text
                                                (if e.source == v.id then
                                                    e.kind

                                                 else
                                                    "incoming: " ++ e.kind
                                                )
                                            ]
                                        , button
                                            (label
                                                (if e.source == v.id then
                                                    e.target

                                                 else
                                                    e.source
                                                )
                                            )
                                            (Select
                                                (if e.source == v.id then
                                                    e.target

                                                 else
                                                    e.source
                                                )
                                            )
                                        ]
                                )
                                (related v.id)
                            )
                        , H.details [ A.class "raw-detail" ]
                            [ H.summary [] [ H.text "Raw details at this revision" ]
                            , H.pre []
                                [ H.text
                                    (if String.length model.detail > 60000 then
                                        String.left 60000 model.detail ++ "\n… Display limited to 60,000 characters."

                                     else
                                        model.detail
                                    )
                                ]
                            , button "Reload details" (Select v.id)
                            ]
                        , H.p [ A.class "semantic-note" ] [ H.text "A changed revision records a value change, not a timing or every recomputation. Effective filters and SSH policy are distinct from peer visibility." ]
                        ]

                    ( _, Just e ) ->
                        [ H.span [ A.class "kind-badge" ] [ H.text "Directed relationship" ], H.h3 [] [ H.text e.kind ], button (label e.source) (Select e.source), H.p [ A.class "relation-direction" ] [ H.text ("↓ " ++ e.kind) ], button (label e.target) (Select e.target), H.p [] [ H.text (meaning e.kind) ], H.code [ A.class "object-id" ] [ H.text e.id ] ]

                    _ ->
                        [ H.div [ A.class "inspector-empty" ] [ H.div [ A.class "selection-symbol", A.attribute "aria-hidden" "true" ] [ S.svg [ SA.width "40", SA.height "40", SA.viewBox "0 0 40 40", SA.fill "none", SA.stroke "currentColor", SA.strokeWidth "1.5" ] [ S.circle [ SA.cx "20", SA.cy "20", SA.r "10" ] [], S.path [ SA.d "M20 3v10 M20 27v10 M3 20h10 M27 20h10" ] [] ] ], H.h3 [] [ H.text "Follow a connection" ], H.p [] [ H.text "Select an object to inspect its properties and related state. Select a line to see the direction and meaning of a relationship." ], H.p [] [ H.text "Tab through objects and press Enter to inspect. Use the arrow keys on the canvas to pan." ] ] ]
               )
            ++ [ H.section [ A.class "recent" ]
                    [ H.h4 [] [ H.text "Recent changes" ]
                    , if List.isEmpty model.recent then
                        H.p []
                            [ H.text
                                (if model.live then
                                    "Waiting for changes after this baseline."

                                 else
                                    "Enable live mode to follow changes."
                                )
                            ]

                      else
                        H.ul [] (List.map (\entry -> H.li [] [ H.text entry ]) model.recent)
                    ]
               ]
        )


meaning : String -> String
meaning kind =
    case kind of
        "depends on" ->
            "The source cell read the target cell when computing its current value."

        "owned by" ->
            "The device belongs to this user namespace. A tagged device's creator is not its owner."

        "tagged with" ->
            "The tag is part of this device's identity; tagged devices are not user-owned."

        "visible to" ->
            "Peer visibility is not permission to initiate traffic. Inspect the effective packet filter and SSH policy separately."

        "advertises" ->
            "The device advertises this route. Advertisement does not imply approval or primary-router selection."

        "approved for" ->
            "This route is approved for the device. Approval is distinct from advertisement and primary-router selection."

        "primary for" ->
            "This device is the selected primary router for the route."

        "compiled from" ->
            "This value derives from policy input. This relationship does not identify an exact source rule."

        "effective filter for" ->
            "The compiled packet filter applies to the target device. SSH policy is inspected separately."

        "contains" ->
            "The source contains this domain object. DERP configuration does not prove an active relay connection."

        _ ->
            "A directed relationship exported from this snapshot."
