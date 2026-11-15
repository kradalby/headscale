module NetworkTopology exposing (view)

import Dict
import Html as H exposing (Html)
import Html.Attributes as A
import Html.Events as Events
import Json.Decode as D
import NetworkData
import Svg as S
import Svg.Attributes as SA


view : (NetworkData.Object -> msg) -> List NetworkData.Object -> List NetworkData.Relationship -> Html msg
view select objects relationships =
    let
        column object =
            if List.member object.kind [ "user", "tag" ] then
                0

            else if object.kind == "node" then
                1

            else
                2

        columns =
            List.range 0 2 |> List.map (\index -> objects |> List.filter (\object -> column object == index) |> List.sortBy .id)

        located =
            columns
                |> List.indexedMap (\index entries -> entries |> List.indexedMap (\row object -> ( object.id, ( object, { x = 24 + toFloat index * 330, y = 68 + toFloat row * 94 } ) )))
                |> List.concat
                |> List.take 200

        positions =
            Dict.fromList located

        height =
            max 260 (100 + 94 * (columns |> List.map List.length |> List.maximum |> Maybe.withDefault 0))

        edge index relationship =
            case ( Dict.get relationship.source positions, Dict.get relationship.target positions ) of
                ( Just ( source, from ), Just ( target, to ) ) ->
                    let
                        rightward =
                            to.x >= from.x

                        x1 =
                            from.x
                                + (if rightward then
                                    230

                                   else
                                    0
                                  )

                        x2 =
                            to.x
                                + (if rightward then
                                    0

                                   else
                                    230
                                  )

                        y1 =
                            from.y + 30

                        y2 =
                            to.y + 30

                        middle =
                            (x1 + x2) / 2

                        curve =
                            "M " ++ String.fromFloat x1 ++ " " ++ String.fromFloat y1 ++ " C " ++ String.fromFloat middle ++ " " ++ String.fromFloat y1 ++ ", " ++ String.fromFloat middle ++ " " ++ String.fromFloat y2 ++ ", " ++ String.fromFloat x2 ++ " " ++ String.fromFloat y2
                    in
                    S.path
                        [ SA.d curve
                        , SA.class "network-topology-edge"
                        , SA.markerEnd "url(#network-arrow)"
                        , A.attribute "aria-label" (source.label ++ " → " ++ relationship.kind ++ " → " ++ target.label)
                        , SA.id ("network-relationship-" ++ String.fromInt index)
                        ]
                        [ S.title [] [ S.text (source.label ++ " → " ++ relationship.kind ++ " → " ++ target.label) ] ]

                _ ->
                    S.g [] []

        node ( _, ( object, point ) ) =
            S.g
                [ SA.transform ("translate(" ++ String.fromFloat point.x ++ "," ++ String.fromFloat point.y ++ ")")
                , SA.class ("network-topology-node " ++ object.kind)
                , A.tabindex 0
                , A.attribute "role" "button"
                , A.attribute "aria-label" (object.label ++ " · " ++ object.kind ++ ". Select to inspect.")
                , Events.onClick (select object)
                , Events.preventDefaultOn "keydown"
                    (D.field "key" D.string
                        |> D.andThen
                            (\key ->
                                if key == "Enter" || key == " " then
                                    D.succeed ( select object, True )

                                else
                                    D.fail "Not an activation key"
                            )
                    )
                ]
                [ S.title [] [ S.text (object.label ++ " · " ++ object.id) ]
                , S.rect [ SA.width "230", SA.height "62", SA.rx "9" ] []
                , S.text_ [ SA.x "12", SA.y "25", SA.class "network-topology-label" ]
                    [ S.text
                        (if String.length object.label > 28 then
                            String.left 27 object.label ++ "…"

                         else
                            object.label
                        )
                    ]
                , S.text_ [ SA.x "12", SA.y "46", SA.class "network-topology-kind" ] [ S.text object.kind ]
                ]
    in
    H.div [ A.class "network-topology-canvas", A.tabindex 0, A.attribute "role" "region", A.attribute "aria-label" "Network relationship diagram. Scroll to explore; Tab to select an object. Equivalent relationships follow below." ]
        [ S.svg [ SA.viewBox ("0 0 950 " ++ String.fromInt height), SA.width "950", SA.height (String.fromInt height), A.attribute "aria-label" "Identities, nodes, routes and services with directed relationships" ]
            ([ S.defs [] [ S.marker [ SA.id "network-arrow", SA.viewBox "0 0 10 10", SA.refX "9", SA.refY "5", SA.markerWidth "7", SA.markerHeight "7", SA.orient "auto-start-reverse" ] [ S.path [ SA.d "M 0 0 L 10 5 L 0 10 z", SA.fill "#8a3153" ] [] ] ] ]
                ++ List.indexedMap (\index label -> S.text_ [ SA.x (String.fromInt (24 + index * 330)), SA.y "30", SA.class "network-topology-heading" ] [ S.text label ]) [ "Identities", "Nodes", "Routes & services" ]
                ++ (relationships |> List.take 1000 |> List.indexedMap edge)
                ++ List.map node located
            )
        ]
