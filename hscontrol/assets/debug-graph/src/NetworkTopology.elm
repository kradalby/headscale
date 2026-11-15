module NetworkTopology exposing (Model, Msg(..), Point, fit, init, layout, setScene, update, view)

import Dict exposing (Dict)
import Html as H exposing (Html)
import Html.Attributes as A
import Html.Events as Events
import Json.Decode as D
import NetworkData exposing (Object, Relationship)
import Set exposing (Set)
import Svg as S
import Svg.Attributes as SA


type alias Point =
    { x : Float, y : Float }


type alias Model =
    { positions : Dict String Point
    , relationships : List Relationship
    , pinned : Set String
    , x : Float
    , y : Float
    , zoom : Float
    , width : Float
    , height : Float
    , drag : Maybe { id : Maybe String, start : Point, origin : Point }
    , moved : Bool
    }


type Msg
    = Resize Float Float
    | Wheel Point Float
    | Start (Maybe String) Point
    | Move Point
    | End
    | Mini Point
    | Pan Float Float
    | Zoom Float
    | Fit (List Object)
    | Arrange (List Object)


init : Model
init =
    { positions = Dict.empty, relationships = [], pinned = Set.empty, x = 0, y = 0, zoom = 1, width = 1000, height = 650, drag = Nothing, moved = False }


number : Float -> String
number =
    String.fromFloat


positions : Float -> List Object -> List Relationship -> Dict String Point
positions viewportWidth objects relationships =
    let
        ordered =
            List.sortBy .id objects

        identities =
            List.filter (\object -> List.member object.kind [ "user", "tag" ]) ordered

        common =
            ordered |> List.filter (\object -> not (List.isEmpty relationships) && List.all (\edge -> edge.source == object.id || edge.target == object.id) relationships) |> List.head

        star anchor =
            let
                children =
                    List.filter (\object -> object.id /= anchor.id) ordered

                childColumns =
                    if viewportWidth < 600 then
                        2

                    else
                        3

                rows =
                    ceiling (toFloat (List.length children) / toFloat childColumns)

                incoming =
                    anchor.kind == "node" && List.all (\edge -> edge.target == anchor.id) relationships

                anchorX =
                    if incoming then
                        750

                    else
                        0

                childX =
                    if incoming then
                        0

                    else
                        280
            in
            if viewportWidth < 600 then
                ( anchor.id
                , { x =
                        if List.length children > 1 then
                            117.5

                        else
                            0
                  , y = 0
                  }
                )
                    :: List.indexedMap (\i object -> ( object.id, { x = toFloat (modBy 2 i * 235), y = 115 + toFloat (i // 2) * 100 } )) children

            else
                ( anchor.id, { x = toFloat anchorX, y = toFloat (max 0 (rows - 1)) * 50 } )
                    :: List.indexedMap (\i object -> ( object.id, { x = toFloat (childX + modBy 3 i * 235), y = toFloat (i // 3) * 100 } )) children

        tags =
            List.filter (\object -> object.kind == "tag") identities

        users =
            List.filter (\object -> object.kind == "user") identities

        parents =
            if List.isEmpty tags then
                users

            else
                tags

        parentIds =
            List.map .id parents

        parentFor object =
            object.relatedIds |> List.filter (\id -> List.member id parentIds) |> List.head

        maxChildren =
            parents |> List.map (\parent -> ordered |> List.filter (\object -> parentFor object == Just parent.id) |> List.length) |> List.maximum |> Maybe.withDefault 0

        columns =
            min
                (if viewportWidth < 600 then
                    2

                 else
                    4
                )
                (max 1 (List.length parents))

        parentY =
            if List.isEmpty tags || List.isEmpty users then
                0

            else
                115

        lanes =
            parents
                |> List.indexedMap
                    (\index parent ->
                        let
                            x =
                                toFloat (modBy columns index * 235)

                            y =
                                toFloat (parentY + (index // columns) * (160 + maxChildren * 90))

                            children =
                                ordered |> List.filter (\object -> object.id /= parent.id && parentFor object == Just parent.id)
                        in
                        ( parent.id, { x = x, y = y } ) :: List.indexedMap (\i object -> ( object.id, { x = x, y = y + 115 + toFloat i * 90 } )) children
                    )
                |> List.concat

        topUsers =
            if List.isEmpty tags then
                []

            else
                users |> List.indexedMap (\i object -> ( object.id, { x = toFloat (columns - 1) * 117.5 + toFloat i * 235, y = 0 } ))

        located =
            Dict.fromList (lanes ++ topUsers)

        bottom =
            Dict.values located |> List.map .y |> List.maximum |> Maybe.withDefault -115

        remaining =
            ordered |> List.filter (\object -> not (Dict.member object.id located)) |> List.indexedMap (\i object -> ( object.id, { x = toFloat (modBy 4 i * 235), y = bottom + 115 + toFloat (i // 4) * 100 } ))
    in
    case common of
        Just anchor ->
            Dict.fromList (star anchor)

        Nothing ->
            Dict.fromList (lanes ++ topUsers ++ remaining)


setScene : List Object -> List Relationship -> Model -> Model
setScene objects relationships model =
    let
        next =
            positions model.width objects relationships

        same =
            Dict.keys next == Dict.keys model.positions
    in
    if same then
        { model | relationships = relationships }

    else
        fit objects { model | positions = next, relationships = relationships, pinned = Set.empty, drag = Nothing }


layout : List Object -> Model -> Model
layout objects model =
    fit objects { model | positions = positions model.width objects model.relationships, pinned = Set.empty }


fit : List Object -> Model -> Model
fit objects model =
    let
        points =
            List.filterMap (\object -> Dict.get object.id model.positions) objects

        left =
            points |> List.map .x |> List.minimum |> Maybe.withDefault 0

        top =
            points |> List.map .y |> List.minimum |> Maybe.withDefault 0

        width =
            (points |> List.map .x |> List.maximum |> Maybe.withDefault 0) - left + 198

        height =
            (points |> List.map .y |> List.maximum |> Maybe.withDefault 0) - top + 66

        padding =
            if model.width < 600 then
                42

            else
                100

        zoom =
            min 1.3 (min ((model.width - padding) / width) ((model.height - padding) / height)) |> max 0.04
    in
    { model | zoom = zoom, x = (model.width - width * zoom) / 2 - left * zoom, y = (model.height - height * zoom) / 2 - top * zoom }


zoomAt : Point -> Float -> Model -> Model
zoomAt point factor model =
    let
        next =
            clamp 0.04 3 (model.zoom * factor)

        ratio =
            next / model.zoom
    in
    { model | zoom = next, x = point.x - (point.x - model.x) * ratio, y = point.y - (point.y - model.y) * ratio }


update : Msg -> Model -> Model
update msg model =
    case msg of
        Resize width height ->
            { model | width = max 1 width, height = max 1 height, x = model.x + (width - model.width) / 2, y = model.y + (height - model.height) / 2 }

        Wheel point delta ->
            zoomAt point (e ^ (-delta * 0.0015)) model

        Zoom factor ->
            zoomAt { x = model.width / 2, y = model.height / 2 } factor model

        Pan x y ->
            { model | x = model.x + x, y = model.y + y }

        Fit objects ->
            fit objects model

        Arrange objects ->
            layout objects model

        Start id point ->
            { model | drag = Just { id = id, start = point, origin = id |> Maybe.andThen (\key -> Dict.get key model.positions) |> Maybe.withDefault { x = model.x, y = model.y } }, moved = False }

        Move point ->
            case model.drag of
                Nothing ->
                    model

                Just drag ->
                    let
                        dx =
                            point.x - drag.start.x

                        dy =
                            point.y - drag.start.y
                    in
                    if not model.moved && dx * dx + dy * dy < 16 then
                        model

                    else
                        case drag.id of
                            Nothing ->
                                { model | x = drag.origin.x + dx, y = drag.origin.y + dy, moved = True }

                            Just id ->
                                { model | positions = Dict.insert id { x = drag.origin.x + dx / model.zoom, y = drag.origin.y + dy / model.zoom } model.positions, pinned = Set.insert id model.pinned, moved = True }

        Mini p ->
            let
                points =
                    Dict.values model.positions

                left =
                    List.minimum (List.map .x points) |> Maybe.withDefault 0

                top =
                    List.minimum (List.map .y points) |> Maybe.withDefault 0

                width =
                    (List.maximum (List.map .x points) |> Maybe.withDefault 0) - left + 198

                height =
                    (List.maximum (List.map .y points) |> Maybe.withDefault 0) - top + 66
            in
            { model | x = model.width / 2 - (left + p.x * width) * model.zoom, y = model.height / 2 - (top + p.y * height) * model.zoom }

        End ->
            { model | drag = Nothing }


pointDecoder : D.Decoder Point
pointDecoder =
    D.map2 Point (D.field "clientX" D.float) (D.field "clientY" D.float)


activation : msg -> D.Decoder ( msg, Bool )
activation message =
    D.field "key" D.string
        |> D.andThen
            (\key ->
                if key == "Enter" || key == " " then
                    D.succeed ( message, True )

                else
                    D.fail "activation only"
            )


view : { onMsg : Msg -> msg, onSelect : Object -> msg, onEdge : Relationship -> msg, selected : Maybe String, selectedEdge : Maybe Relationship } -> List Object -> List Relationship -> Model -> Html msg
view config objects relationships model =
    let
        objectName id =
            objects |> List.filter (\object -> object.id == id) |> List.head |> Maybe.map .label |> Maybe.withDefault id

        point id =
            Dict.get id model.positions |> Maybe.withDefault { x = 0, y = 0 }

        keyDecoder =
            D.field "key" D.string
                |> D.andThen
                    (\key ->
                        case key of
                            "ArrowLeft" ->
                                D.succeed ( config.onMsg (Pan 45 0), True )

                            "ArrowRight" ->
                                D.succeed ( config.onMsg (Pan -45 0), True )

                            "ArrowUp" ->
                                D.succeed ( config.onMsg (Pan 0 45), True )

                            "ArrowDown" ->
                                D.succeed ( config.onMsg (Pan 0 -45), True )

                            "+" ->
                                D.succeed ( config.onMsg (Zoom 1.2), True )

                            "=" ->
                                D.succeed ( config.onMsg (Zoom 1.2), True )

                            "-" ->
                                D.succeed ( config.onMsg (Zoom (1 / 1.2)), True )

                            "0" ->
                                D.succeed ( config.onMsg (Fit objects), True )

                            _ ->
                                D.fail "camera keys only"
                    )

        edge index relationship =
            let
                from =
                    point relationship.source

                to =
                    point relationship.target

                dx =
                    to.x - from.x

                dy =
                    to.y - from.y

                scale =
                    max (abs dx / 105) (abs dy / 40) |> max 1

                start =
                    { x = from.x + 99 + dx / scale, y = from.y + 33 + dy / scale }

                end =
                    { x = to.x + 99 - dx / scale, y = to.y + 33 - dy / scale }

                path =
                    if abs dx < 1 then
                        let
                            side =
                                from.x + 219
                        in
                        "M"
                            ++ number (from.x + 198)
                            ++ " "
                            ++ number (from.y + 33)
                            ++ " C"
                            ++ number side
                            ++ " "
                            ++ number (from.y + 33)
                            ++ " "
                            ++ number side
                            ++ " "
                            ++ number (to.y + 33)
                            ++ " "
                            ++ number (to.x + 198)
                            ++ " "
                            ++ number (to.y + 33)

                    else
                        "M" ++ number start.x ++ " " ++ number start.y ++ " C" ++ number start.x ++ " " ++ number ((start.y + end.y) / 2) ++ " " ++ number end.x ++ " " ++ number ((start.y + end.y) / 2) ++ " " ++ number end.x ++ " " ++ number end.y

                selected =
                    config.selectedEdge == Just relationship
            in
            S.g
                [ A.attribute "data-kind" relationship.kind
                , SA.class
                    ("edge"
                        ++ (if selected then
                                " selected"

                            else
                                ""
                           )
                    )
                , A.attribute "tabindex" "0"
                , A.attribute "role" "button"
                , A.attribute "aria-label" (objectName relationship.source ++ " → " ++ relationship.kind ++ " → " ++ objectName relationship.target)
                , Events.stopPropagationOn "pointerdown" (D.succeed ( config.onMsg End, True ))
                , Events.onClick (config.onEdge relationship)
                , Events.preventDefaultOn "keydown" (activation (config.onEdge relationship))
                , SA.id ("network-edge-" ++ String.fromInt index)
                ]
                [ S.title [] [ S.text relationship.kind ]
                , S.path [ SA.d path, SA.class "edge-hit" ] []
                , S.path [ SA.d path, SA.class "edge-line", SA.markerEnd "url(#arrow-active)" ] []
                , S.text_ [ SA.x (number ((start.x + end.x) / 2)), SA.y (number ((start.y + end.y) / 2 - 8)), SA.class "edge-label", SA.textAnchor "middle" ] [ S.text relationship.kind ]
                ]

        node object =
            let
                p =
                    point object.id

                selected =
                    config.selected == Just object.id

                click =
                    if model.moved then
                        config.onMsg End

                    else
                        config.onSelect object

                symbol =
                    case object.kind of
                        "node" ->
                            "M12 10H29V23H12Z M9 27H32 M20 23V27"

                        "tag" ->
                            "M12 11H23L30 18L23 25H12Z"

                        "route" ->
                            "M11 15H22V10L30 18L22 26V21H11Z"

                        "user" ->
                            "M16 12A5 5 0 1 0 26 12A5 5 0 1 0 16 12 M11 27Q11 18 21 18Q31 18 31 27Z"

                        _ ->
                            "M13 11H28V25H13Z"
            in
            S.g
                [ SA.class
                    ("vertex "
                        ++ object.kind
                        ++ (if selected then
                                " selected"

                            else
                                ""
                           )
                    )
                , SA.transform ("translate(" ++ number p.x ++ "," ++ number p.y ++ ")")
                , SA.id ("graph-object-" ++ object.id)
                , A.attribute "tabindex" "0"
                , A.attribute "role" "button"
                , A.attribute "aria-label" (object.label ++ ", " ++ object.kind)
                , A.attribute "aria-pressed"
                    (if selected then
                        "true"

                     else
                        "false"
                    )
                , Events.stopPropagationOn "pointerdown" (D.map (\p2 -> ( config.onMsg (Start (Just object.id) p2), True )) pointDecoder)
                , Events.onClick click
                , Events.preventDefaultOn "keydown" (activation (config.onSelect object))
                ]
                [ S.title [] [ S.text (object.label ++ "\n" ++ object.id) ]
                , S.rect [ SA.class "node-body", SA.width "198", SA.height "66", SA.rx "13" ] []
                , if object.kind == "node" then
                    S.g [ SA.class "device-glyph" ]
                        [ S.rect [ SA.x "11", SA.y "8", SA.width "18", SA.height "13", SA.rx "2", SA.class "glyph-frame" ] []
                        , S.rect [ SA.x "14", SA.y "11", SA.width "12", SA.height "7", SA.rx "1", SA.class "glyph-pink" ] []
                        , S.path [ SA.d "M9 23H31L29 26H11Z", SA.class "glyph-frame" ] []
                        ]

                  else
                    S.path [ SA.class "node-symbol", SA.d symbol ] []
                , S.text_ [ SA.class "node-kind", SA.x "37", SA.y "21" ]
                    [ S.text
                        ((if object.memberCount > 0 then
                            String.fromInt object.memberCount ++ " devices · explore"

                          else if object.kind == "service" then
                            object.provenance

                          else
                            object.kind
                         )
                            ++ (if Set.member object.id model.pinned then
                                    " / pinned"

                                else
                                    ""
                               )
                        )
                    ]
                , S.text_ [ SA.class "node-label", SA.x "14", SA.y "47" ]
                    [ S.text
                        (if String.length object.label > 25 then
                            String.left 24 object.label ++ "…"

                         else
                            object.label
                        )
                    ]
                , case object.online of
                    Just online ->
                        S.circle
                            [ SA.cx "181"
                            , SA.cy "17"
                            , SA.r "3"
                            , SA.fill
                                (if online then
                                    "#258663"

                                 else
                                    "#aaa"
                                )
                            ]
                            []

                    Nothing ->
                        S.text ""
                ]

        miniPoints =
            Dict.values model.positions

        miniLeft =
            List.minimum (List.map .x miniPoints) |> Maybe.withDefault 0

        miniTop =
            List.minimum (List.map .y miniPoints) |> Maybe.withDefault 0

        miniWidth =
            (List.maximum (List.map .x miniPoints) |> Maybe.withDefault 0) - miniLeft + 198

        miniHeight =
            (List.maximum (List.map .y miniPoints) |> Maybe.withDefault 0) - miniTop + 66

        button title message =
            H.button [ A.type_ "button", Events.onClick (config.onMsg message) ] [ H.text title ]
    in
    H.div [ A.class "network-canvas", A.style "position" "relative", A.style "height" "100%" ]
        [ S.svg
            [ SA.id "graph-canvas"
            , SA.class "graph-canvas"
            , SA.width "100%"
            , SA.height "100%"
            , SA.viewBox ("0 0 " ++ number model.width ++ " " ++ number model.height)
            , A.attribute "tabindex" "0"
            , A.attribute "role" "group"
            , A.attribute "aria-label" "Interactive network graph. Drag background to pan, drag objects to pin, scroll to zoom. Arrow keys pan, plus and minus zoom, zero fits, Enter selects focused objects and relationships."
            , Events.on "pointerdown" (D.map (Start Nothing >> config.onMsg) pointDecoder)
            , Events.on "pointermove" (D.map (Move >> config.onMsg) pointDecoder)
            , Events.on "pointerup" (D.succeed (config.onMsg End))
            , Events.on "pointercancel" (D.succeed (config.onMsg End))
            , Events.on "pointerleave" (D.succeed (config.onMsg End))
            , Events.preventDefaultOn "wheel" (D.map2 (\p delta -> ( config.onMsg (Wheel p delta), True )) (D.field "graphPoint" (D.map2 Point (D.field "x" D.float) (D.field "y" D.float))) (D.field "deltaY" D.float))
            , Events.preventDefaultOn "keydown" keyDecoder
            ]
            [ S.defs [] [ S.marker [ SA.id "arrow-active", SA.viewBox "0 0 10 10", SA.refX "10", SA.refY "5", SA.markerWidth "7", SA.markerHeight "7", SA.orient "auto" ] [ S.path [ SA.d "M0 0L10 5L0 10Z", SA.fill "context-stroke" ] [] ] ]
            , S.g [ SA.transform ("translate(" ++ number model.x ++ "," ++ number model.y ++ ") scale(" ++ number model.zoom ++ ")") ]
                ((relationships |> List.filter (\r -> Dict.member r.source model.positions && Dict.member r.target model.positions) |> List.indexedMap edge) ++ List.map node objects)
            ]
        , H.details [ A.class "minimap" ]
            [ H.summary [] [ H.text "Overview" ]
            , S.svg [ SA.id "graph-minimap", SA.viewBox (String.join " " (List.map number [ miniLeft, miniTop, miniWidth, miniHeight ])), SA.preserveAspectRatio "none", Events.on "click" (D.field "miniPoint" (D.map2 Point (D.field "x" D.float) (D.field "y" D.float)) |> D.map (Mini >> config.onMsg)) ]
                (List.map (\p -> S.rect [ SA.x (number p.x), SA.y (number p.y), SA.width "198", SA.height "66", SA.rx "10", SA.fill "#d4bbc4" ] []) miniPoints
                    ++ [ S.rect [ SA.class "minimap-viewport", SA.x (number (-model.x / model.zoom)), SA.y (number (-model.y / model.zoom)), SA.width (number (model.width / model.zoom)), SA.height (number (model.height / model.zoom)) ] [] ]
                )
            ]
        , H.div [ A.class "camera-controls" ] [ button "−" (Zoom (1 / 1.2)), H.span [] [ H.text (String.fromInt (round (model.zoom * 100)) ++ "%") ], button "+" (Zoom 1.2), button "Fit" (Fit objects), button "Arrange" (Arrange objects) ]
        , H.div [ A.class "canvas-help" ] [ H.text "Drag to explore · Scroll to zoom · Drag an object to pin · 0 to fit" ]
        ]
