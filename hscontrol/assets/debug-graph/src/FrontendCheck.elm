port module FrontendCheck exposing (main)

import Dict
import Graph
import Json.Decode as D
import Json.Encode as E
import Main
import Platform
import Set


port results : E.Value -> Cmd msg


main : Program () () Never
main =
    Platform.worker
        { init = \_ -> ( (), results (E.list (\( name, passed ) -> E.object [ ( "name", E.string name ), ( "passed", E.bool passed ) ]) checks) )
        , update = \msg _ -> never msg
        , subscriptions = \_ -> Sub.none
        }


sceneJson : String
sceneJson =
    """{"revision":"90071992547409930","timestamp":"2026-10-25T12:00:00Z","perspective":"core","search":"","focus":"","vertices":[{"id":"cell:nodes","label":"nodes","kind":"input","summary":"2 devices","changedAt":"90071992547409929","properties":{"count":"2"}},{"id":"cell:index","label":"index","kind":"derived","summary":"Indexed nodes","changedAt":"90071992547409930","properties":{}}],"edges":[{"id":"edge:index:nodes","source":"cell:index","target":"cell:nodes","kind":"depends on"}],"totalNodes":2,"matchedNodes":2,"shownNodes":2,"limit":200,"truncated":false,"policyError":""}"""


patchJson : String
patchJson =
    """{"baseRevision":"90071992547409930","revision":"90071992547409931","timestamp":"2026-10-25T12:00:01Z","vertices":[{"id":"cell:index","label":"index","kind":"derived","summary":"Updated index","changedAt":"90071992547409931","properties":{"count":"1"}}],"edges":[],"removedVertices":["cell:nodes"],"removedEdges":[],"totalNodes":1,"matchedNodes":1,"shownNodes":1,"limit":200,"truncated":false,"policyError":""}"""


incoming : Int -> String -> E.Value -> Main.Msg
incoming generation kind data =
    Main.Incoming (E.object [ ( "generation", E.int generation ), ( "type", E.string kind ), ( "data", data ) ])


run msg model =
    Main.update msg model |> Tuple.first


checks : List ( String, Bool )
checks =
    case ( ( D.decodeString Graph.sceneDecoder sceneJson, D.decodeString Graph.patchDecoder patchJson ), ( D.decodeString D.value sceneJson, D.decodeString D.value patchJson ) ) of
        ( ( Ok scene, Ok patch ), ( Ok sceneValue, Ok patchValue ) ) ->
            let
                baseline =
                    Main.initial

                loaded =
                    run (incoming 0 "snapshot" sceneValue) baseline

                selected =
                    run (Main.Select "cell:index") loaded

                updated =
                    run (incoming 0 "patch" patchValue) selected

                removed =
                    run (incoming 0 "patch" patchValue) (run (Main.Select "cell:nodes") loaded)

                point =
                    { x = 250, y = 160 }

                zoomed =
                    Main.zoomAt point 1.5 loaded

                worldPoint model =
                    ( (point.x - model.camera.x) / model.camera.zoom, (point.y - model.camera.y) / model.camera.zoom )

                oldPoint =
                    Dict.get "cell:index" loaded.positions

                dragStart =
                    run (Main.Start (Just "cell:index") { x = 10, y = 10 }) loaded

                dragged =
                    dragStart |> run (Main.Move { x = 70, y = 40 }) |> run Main.End |> run (Main.Activate "cell:index")

                clicked =
                    dragStart |> run (Main.Move { x = 11, y = 11 }) |> run Main.End |> run (Main.Activate "cell:index")

                edgeAfterPan =
                    loaded
                        |> run (Main.Start Nothing { x = 0, y = 0 })
                        |> run (Main.Move { x = 80, y = 40 })
                        |> run Main.End
                        |> run Main.StartEdge
                        |> run Main.End
                        |> run (Main.Activate "edge:index:nodes")

                detail revision id value =
                    E.object [ ( "revision", E.string revision ), ( "id", E.string id ), ( "data", E.string value ) ]

                near ( x, y ) ( a, b ) =
                    abs (x - a) < 0.0001 && abs (y - b) < 0.0001

                changed =
                    Graph.applyPatch patch scene |> Result.toMaybe

                mismatch =
                    run (incoming 0 "patch" patchValue) updated

                largeScene =
                    { scene | perspective = "world", edges = [], vertices = List.range 1 200 |> List.map (\n -> { id = "node:" ++ String.fromInt n, label = "Device " ++ String.fromInt n, kind = "node", summary = "", changedAt = "1", properties = Dict.empty }) }

                large =
                    Main.accept largeScene baseline |> Main.fit

                insideCanvas p =
                    p.x
                        * large.camera.zoom
                        + large.camera.x
                        >= 0
                        && p.y
                        * large.camera.zoom
                        + large.camera.y
                        >= 0
                        && (p.x + 198)
                        * large.camera.zoom
                        + large.camera.x
                        <= large.width
                        && (p.y + 66)
                        * large.camera.zoom
                        + large.camera.y
                        <= large.height

                searched =
                    run Main.Submit (run (Main.Search "  device-name  ") loaded)

                expanded =
                    run (Main.Expand "node:1") searched

                liveQuery =
                    { selected | live = True, perspective = "world", focus = "node:1", submitted = "device-name", search = "draft" }

                restored =
                    run (incoming 0 "restore" E.null) liveQuery

                failedConnection =
                    run (incoming 0 "error" (E.string "Live connection closed. Retry to reconnect.")) liveQuery

                edgeOnly removedEdges edges =
                    E.object
                        [ ( "baseRevision", E.string scene.revision )
                        , ( "revision", E.string patch.revision )
                        , ( "timestamp", E.string patch.timestamp )
                        , ( "vertices", E.list identity [] )
                        , ( "edges", E.list (\edge -> E.object [ ( "id", E.string edge.id ), ( "source", E.string edge.source ), ( "target", E.string edge.target ), ( "kind", E.string edge.kind ) ]) edges )
                        , ( "removedVertices", E.list E.string [] )
                        , ( "removedEdges", E.list E.string removedEdges )
                        , ( "totalNodes", E.int 2 )
                        , ( "matchedNodes", E.int 2 )
                        , ( "shownNodes", E.int 2 )
                        , ( "limit", E.int 200 )
                        , ( "truncated", E.bool False )
                        , ( "policyError", E.string "" )
                        ]

                changedEdge =
                    { id = "edge:index:nodes", source = "cell:index", target = "cell:nodes", kind = "visible to" }

                edgeChanged =
                    run (incoming 0 "patch" (edgeOnly [] [ changedEdge ])) loaded

                edgeAdded =
                    run (incoming 0 "patch" (edgeOnly [] [ { changedEdge | id = "edge:new" } ])) loaded

                edgeRemoved =
                    run (incoming 0 "patch" (edgeOnly [ changedEdge.id ] [])) (run (Main.Select changedEdge.id) loaded)

                manyEdgeChanges =
                    run (incoming 0 "patch" (edgeOnly [] (List.range 1 20 |> List.map (\n -> { changedEdge | id = "edge:new:" ++ String.fromInt n })))) loaded

                origin =
                    { x = 0, y = 0 }

                right =
                    Main.edgePoints origin { x = 300, y = 0 }

                left =
                    Main.edgePoints { x = 300, y = 0 } origin

                below =
                    Main.edgePoints origin { x = 0, y = 150 }

                above =
                    Main.edgePoints { x = 0, y = 150 } origin

                world =
                    { loaded | perspective = "world", scene = Just { scene | perspective = "world" } }

                started =
                    run Main.SettleLayout world

                layoutStep =
                    run (Main.SettleStep world.generation) started

                finish model =
                    List.foldl (\_ current -> run (Main.SettleStep world.generation) current) model (List.range 1 32)

                settled =
                    finish started

                pinnedLayout =
                    finish (run Main.SettleLayout { world | pinned = Set.singleton "cell:index" })

                distant =
                    Dict.fromList [ ( "cell:index", { x = 0, y = 0 } ), ( "cell:nodes", { x = 1000, y = 0 } ) ]

                relaxed =
                    Main.relax scene Set.empty distant

                distance positions =
                    case ( Dict.get "cell:index" positions, Dict.get "cell:nodes" positions ) of
                        ( Just a, Just b ) ->
                            abs (b.x - a.x)

                        _ ->
                            0

                coincident =
                    Dict.map (\_ _ -> { x = 0, y = 0 }) distant

                separated =
                    Main.relax scene Set.empty coincident

                largeSettled =
                    List.foldl (\_ positions -> Main.relax largeScene Set.empty positions) large.positions (List.range 1 32)

                filtered =
                    run (Main.SettleStep world.generation) (run Main.SettleLayout { world | positions = distant, hidden = Set.singleton "input" })

                withoutRelation =
                    run (Main.SettleStep world.generation) (run Main.SettleLayout { world | positions = distant, hiddenRelations = Set.singleton "depends on" })

                noOverlaps positions =
                    Dict.toList positions |> List.all (\( id, a ) -> Dict.toList positions |> List.all (\( otherId, b ) -> id == otherId || abs (a.x - b.x) >= 198 || abs (a.y - b.y) >= 66))

                browserScene =
                    { scene
                        | perspective = "world"
                        , vertices = [ ( "cell:derp-map", "input" ), ( "cell:dns", "input" ), ( "cell:index", "derived" ), ( "cell:node-caps", "derived" ), ( "cell:nodes", "input" ), ( "cell:peer-policy", "derived" ), ( "cell:peers", "derived" ), ( "cell:policy", "derived" ), ( "cell:policy-nodes", "derived" ), ( "cell:policy-source", "input" ), ( "cell:policy-users", "derived" ), ( "cell:primaries", "derived" ), ( "cell:users", "input" ), ( "filter:1", "filter" ), ( "filter:2", "filter" ), ( "filter:3", "filter" ), ( "filter:4", "filter" ), ( "filter:5", "filter" ), ( "filter:6", "filter" ), ( "filter:7", "filter" ), ( "filter:8", "filter" ), ( "node:1", "node" ), ( "node:2", "node" ), ( "node:3", "node" ), ( "node:4", "node" ), ( "node:5", "node" ), ( "node:6", "node" ), ( "node:7", "node" ), ( "node:8", "node" ), ( "route:10.24.0.0/16", "route" ), ( "tag:tag:infra", "tag" ), ( "user:1", "user" ), ( "user:2", "user" ) ] |> List.map (\( id, kind ) -> { id = id, kind = kind, label = id, summary = "", changedAt = "", properties = Dict.empty })
                        , edges = [ ( "cell:index", "cell:nodes", "depends on" ), ( "cell:node-caps", "cell:policy", "depends on" ), ( "cell:nodes", "node:1", "contains" ), ( "cell:nodes", "node:2", "contains" ), ( "cell:nodes", "node:3", "contains" ), ( "cell:nodes", "node:4", "contains" ), ( "cell:nodes", "node:5", "contains" ), ( "cell:nodes", "node:6", "contains" ), ( "cell:nodes", "node:7", "contains" ), ( "cell:nodes", "node:8", "contains" ), ( "cell:peer-policy", "cell:policy", "depends on" ), ( "cell:peers", "cell:policy", "depends on" ), ( "cell:peers", "cell:policy-nodes", "depends on" ), ( "cell:policy-nodes", "cell:nodes", "depends on" ), ( "cell:policy-users", "cell:users", "depends on" ), ( "cell:policy", "cell:policy-source", "compiled from" ), ( "cell:policy", "cell:policy-nodes", "depends on" ), ( "cell:policy", "cell:policy-source", "depends on" ), ( "cell:policy", "cell:policy-users", "depends on" ), ( "cell:primaries", "cell:nodes", "depends on" ), ( "filter:1", "cell:policy", "compiled from" ), ( "filter:1", "node:1", "effective filter for" ), ( "filter:2", "cell:policy", "compiled from" ), ( "filter:2", "node:2", "effective filter for" ), ( "filter:3", "cell:policy", "compiled from" ), ( "filter:3", "node:3", "effective filter for" ), ( "filter:4", "cell:policy", "compiled from" ), ( "filter:4", "node:4", "effective filter for" ), ( "filter:5", "cell:policy", "compiled from" ), ( "filter:5", "node:5", "effective filter for" ), ( "filter:6", "cell:policy", "compiled from" ), ( "filter:6", "node:6", "effective filter for" ), ( "filter:7", "cell:policy", "compiled from" ), ( "filter:7", "node:7", "effective filter for" ), ( "filter:8", "cell:policy", "compiled from" ), ( "filter:8", "node:8", "effective filter for" ), ( "node:1", "user:1", "owned by" ), ( "node:1", "node:6", "visible to" ), ( "node:2", "user:1", "owned by" ), ( "node:2", "node:6", "visible to" ), ( "node:3", "user:2", "owned by" ), ( "node:3", "node:6", "visible to" ), ( "node:4", "user:2", "owned by" ), ( "node:4", "node:6", "visible to" ), ( "node:5", "tag:tag:infra", "tagged with" ), ( "node:5", "node:6", "visible to" ), ( "node:6", "route:10.24.0.0/16", "approved for" ), ( "node:6", "tag:tag:infra", "tagged with" ), ( "node:7", "tag:tag:infra", "tagged with" ), ( "node:7", "node:6", "visible to" ), ( "node:8", "tag:tag:infra", "tagged with" ), ( "node:8", "node:6", "visible to" ) ] |> List.indexedMap (\index ( source, target, kind ) -> { id = "fixture:" ++ String.fromInt index, source = source, target = target, kind = kind })
                    }

                browserModel =
                    Main.accept browserScene { baseline | perspective = "world", pinned = Set.singleton "node:6" }

                browserSettled =
                    finish (run Main.SettleLayout browserModel)

                collisionPinned =
                    Main.separate scene.vertices (Set.singleton "cell:nodes") coincident

                packed =
                    Main.separate largeScene.vertices Set.empty (Dict.map (\_ _ -> { x = 0, y = 0 }) large.positions)

                cameraActions =
                    [ Main.Fit, Main.Zoom 1.25, Main.Wheel { x = 100, y = 80 } -1, Main.Pan 40 0, Main.Mini { x = 0.3, y = 0.7 } ]

                unselected =
                    run Main.CloseInspector selected

                parallel =
                    [ { id = "a", source = "node:1", target = "route:1", kind = "advertises" }
                    , { id = "b", source = "node:1", target = "route:1", kind = "approved for" }
                    , { id = "c", source = "route:1", target = "node:1", kind = "reverse" }
                    ]

                offsets =
                    Main.edgeOffsets parallel

                curves =
                    parallel
                        |> List.map
                            (\edge ->
                                if edge.source == "node:1" then
                                    Main.edgeCurve (Dict.get edge.id offsets |> Maybe.withDefault 0) { x = 0, y = 0 } { x = 300, y = 0 }

                                else
                                    Main.edgeCurve (Dict.get edge.id offsets |> Maybe.withDefault 0) { x = 300, y = 0 } { x = 0, y = 0 }
                            )

                oldInstance =
                    Main.accept { scene | revision = "previous:42" } baseline |> run (Main.Select "cell:index")

                restarted =
                    D.decodeString D.value (String.replace "\"revision\":\"90071992547409930\"" "\"revision\":\"current:43\"" sceneJson)
                        |> Result.withDefault E.null
                        |> incoming 0 "snapshot"
                        |> (\msg -> run msg oldInstance)

                oldAnswered =
                    run (incoming 0 "detail" (detail "previous:42" "cell:index" "old")) restarted

                oldFailed =
                    run (incoming 0 "detailError" (E.object [ ( "id", E.string "cell:index" ), ( "revision", E.string "previous:42" ), ( "message", E.string "old failure" ) ])) restarted

                newAnswered =
                    run (incoming 0 "detail" (detail "current:43" "cell:index" "new")) oldAnswered

                inspectorOpened =
                    run Main.FocusInspector loaded
            in
            [ ( "shared scene decoder preserves string revisions and properties", scene.revision == "90071992547409930" && (List.head scene.vertices |> Maybe.andThen (\v -> Dict.get "count" v.properties)) == Just "2" )
            , ( "shared patch decoder preserves string revision", patch.revision == "90071992547409931" )
            , ( "patch upserts and removes vertices", Maybe.map (\s -> List.map .id s.vertices) changed == Just [ "cell:index" ] )
            , ( "patch removes edges incident to removed vertices", Maybe.map .edges changed == Just [] )
            , ( "patch updates properties and metadata", Maybe.map .totalNodes changed == Just 1 && (changed |> Maybe.andThen (\s -> List.head s.vertices) |> Maybe.map .summary) == Just "Updated index" )
            , ( "mismatched base revision rejected", Graph.applyPatch { patch | baseRevision = "old" } scene == Err "Revision changed; requesting a fresh baseline." )
            , ( "selection survives update", updated.selected == Just "cell:index" )
            , ( "removed selection clears with notice", removed.selected == Nothing && String.contains "removed" removed.notice )
            , ( "removed edge selection clears", Graph.selection (Maybe.withDefault scene changed) (Just "edge:index:nodes") == Nothing )
            , ( "old scene generation discarded", (run (incoming -1 "snapshot" sceneValue) updated).scene == updated.scene )
            , ( "revision mismatch requests new generation", mismatch.generation == updated.generation + 1 )
            , ( "reconnect baseline has no added highlights", Dict.isEmpty (run (incoming 0 "snapshot" sceneValue) updated).highlights )
            , ( "reconnect clears obsolete recent changes", List.isEmpty (run (incoming 0 "snapshot" sceneValue) updated).recent )
            , ( "a patch leaves the selection's pending detail request to finish", updated.detailRequest == selected.detailRequest && selected.detailRequest == Just ( "cell:index", scene.revision ) )
            , ( "earlier revision details are shown and the current requested", String.contains "stale" (run (incoming 0 "detail" (detail scene.revision "cell:index" "stale")) updated).detail && (run (incoming 0 "detail" (detail scene.revision "cell:index" "stale")) updated).detailRequest == Just ( "cell:index", patch.revision ) )
            , ( "old selection details discarded", (run (incoming 0 "detail" (detail scene.revision "cell:index" "stale")) unselected).detail == unselected.detail )
            , ( "current revision details accepted", (run (incoming 0 "detail" (detail patch.revision "cell:index" "current")) updated).detail == "\"current\"" )
            , ( "zoom is anchored at cursor", near (worldPoint loaded) (worldPoint zoomed) )
            , ( "200-object World scene fits within canvas", Dict.size large.positions == 200 && List.all insideCanvas (Dict.values large.positions) )
            , ( "200-object positions are distinct", (Dict.values large.positions |> List.map (\p -> ( p.x, p.y )) |> Set.fromList |> Set.size) == 200 )
            , ( "rightward arrows meet right source and left target borders", right.source == { x = 198, y = 33 } && right.target == { x = 300, y = 33 } && right.direction == 1 )
            , ( "leftward arrows meet left source and right target borders", left.source == right.target && left.target == right.source && left.direction == -1 )
            , ( "downward arrows meet bottom source and top target borders", below.source == { x = 99, y = 66 } && below.target == { x = 99, y = 150 } && not below.horizontal && below.direction == 1 )
            , ( "upward arrows meet top source and bottom target borders", above.source == below.target && above.target == below.source && above.direction == -1 )
            , ( "parallel and reverse relationships have distinct curves", List.map .path curves |> Set.fromList |> Set.size |> (==) 3 )
            , ( "parallel offsets do not depend on input order", Main.edgeOffsets (List.reverse parallel) == offsets )
            , ( "curved arrows retain directed endpoints", List.head curves |> Maybe.map (\curve -> curve.source == right.source && curve.target == right.target && curve.control2.x < curve.target.x) |> Maybe.withDefault False )
            , ( "overlapping and coincident cards retain distinct paths", List.map (\offset -> (Main.edgeCurve offset { x = 0, y = 0 } { x = 0, y = 0 }).path) [ -36, 0, 36 ] |> Set.fromList |> Set.size |> (==) 3 )
            , ( "object skip targets visible object", Main.objectFocusTarget loaded == "graph-object-cell:nodes" && Main.objectFocusTarget { loaded | hidden = Set.singleton "input" } == "graph-object-cell:index" )
            , ( "empty object skip falls back to canvas", Main.objectFocusTarget { loaded | hidden = Set.fromList [ "input", "derived" ] } == "graph-canvas" )
            , ( "inspector can open without selection and close again", inspectorOpened.inspectorOpen && not (run Main.CloseInspector inspectorOpened).inspectorOpen )
            , ( "revision display preserves numeric suffix exactly", Main.revisionNumber "instance:90071992547409930" == "90071992547409930" && Main.revisionNumber "42" == "42" )
            , ( "details from another server instance are rejected", (run (incoming 0 "detail" (detail "current:42" "cell:index" "wrong instance")) oldInstance).detail == oldInstance.detail )
            , ( "current server instance details remain accepted", (run (incoming 0 "detail" (detail "previous:42" "cell:index" "current")) oldInstance).detail == "\"current\"" )
            , ( "a baseline from another server instance supersedes the pending detail request", oldInstance.detailRequest == Just ( "cell:index", "previous:42" ) && restarted.detailRequest == Just ( "cell:index", "current:43" ) )
            , ( "the earlier instance's answer is dropped and the new request stays pending", oldAnswered.detail == restarted.detail && oldAnswered.detailRequest == Just ( "cell:index", "current:43" ) )
            , ( "the earlier instance's failure is dropped and the new request stays pending", oldFailed.detail == restarted.detail && oldFailed.detailRequest == Just ( "cell:index", "current:43" ) )
            , ( "the new instance's answer is shown after the earlier one was dropped", newAnswered.detail == "\"new\"" && newAnswered.detailRequest == Nothing )
            , ( "force layout is World-only and opt-in", loaded.settling == Nothing && (run Main.SettleLayout loaded).settling == Nothing && started.settling /= Nothing )
            , ( "settling preserves displayed positions until complete", layoutStep.positions == world.positions && layoutStep.settling /= Nothing )
            , ( "force layout stops after bounded steps", settled.settling == Nothing && (run (Main.SettleStep world.generation) settled).positions == settled.positions )
            , ( "force layout keeps pins fixed", Dict.get "cell:index" pinnedLayout.positions == Dict.get "cell:index" world.positions )
            , ( "spring attracts distant connected objects", distance relaxed < distance distant )
            , ( "repulsion separates coincident objects deterministically", Dict.get "cell:index" separated /= Dict.get "cell:nodes" separated && separated == Main.relax scene Set.empty coincident )
            , ( "scene change cancels settling and stale steps", (run Main.Refresh started).settling == Nothing && (run (Main.SettleStep world.generation) (run Main.Refresh started)).positions == world.positions )
            , ( "drag cancels pending layout", (run (Main.Start (Just "cell:index") { x = 0, y = 0 }) started).settling == Nothing )
            , ( "live patch cancels pending layout without moving objects", (run (incoming 0 "patch" patchValue) started).settling == Nothing && Dict.get "cell:index" (run (incoming 0 "patch" patchValue) started).positions == Dict.get "cell:index" world.positions )
            , ( "property-only live updates retain pending layout", (run (incoming 0 "patch" (edgeOnly [] [])) started).settling /= Nothing && (finish (run (incoming 0 "patch" (edgeOnly [] [])) started)).settling == Nothing )
            , ( "bounded 200-object force layout remains finite", Dict.size largeSettled == 200 && List.all (\p -> not (isNaN p.x || isNaN p.y || isInfinite p.x || isInfinite p.y)) (Dict.values largeSettled) )
            , ( "settling ignores hidden objects and their incident relationships", Maybe.map .positions filtered.settling == Just distant )
            , ( "settling excludes hidden relationship springs", (Maybe.map (\work -> distance work.positions) withoutRelation.settling |> Maybe.withDefault 0) >= distance distant )
            , ( "filter changes cancel pending settling", (run (Main.Category "input") started).settling == Nothing && (run (Main.Relation "depends on") started).settling == Nothing )
            , ( "200-object settling displacement is bounded", Dict.toList largeSettled |> List.all (\( id, settledPoint ) -> Dict.get id large.positions |> Maybe.map (\old -> abs (settledPoint.x - old.x) <= 768 && abs (settledPoint.y - old.y) <= 768) |> Maybe.withDefault False) )
            , ( "settled browser 33-object 52-edge fixture has no card overlaps", List.length browserScene.vertices == 33 && List.length browserScene.edges == 52 && noOverlaps browserSettled.positions )
            , ( "final separation preserves browser fixture pin", Dict.get "node:6" browserSettled.positions == Dict.get "node:6" browserModel.positions )
            , ( "final separation clears overlap with fixed card", noOverlaps collisionPinned && Dict.get "cell:nodes" collisionPinned == Dict.get "cell:nodes" coincident )
            , ( "final separation preserves hidden objects", Main.separate (List.filter (\v -> v.id == "cell:index") scene.vertices) Set.empty coincident == coincident )
            , ( "200 coincident objects separate with bounded work and positions", Dict.size packed == 200 && noOverlaps packed && List.all (\p -> p.x == 0 && p.y >= 0 && p.y <= 199 * 78) (Dict.values packed) )
            , ( "all camera actions cancel settling and reject late completion"
              , List.all
                    (\action ->
                        let
                            moved =
                                run action started
                        in
                        moved.settling == Nothing && (run (Main.SettleStep world.generation) moved).camera == moved.camera && (run (Main.SettleStep world.generation) moved).positions == moved.positions
                    )
                    cameraActions
              )
            , ( "positions survive patch", Dict.get "cell:index" updated.positions == oldPoint )
            , ( "drag pins and moves without selecting", Set.member "cell:index" dragged.pinned && Dict.get "cell:index" dragged.positions /= oldPoint && dragged.selected == Nothing )
            , ( "click tolerates tiny motion without pinning", clicked.selected == Just "cell:index" && not (Set.member "cell:index" clicked.pinned) )
            , ( "first edge click after background pan selects edge", edgeAfterPan.selected == Just "edge:index:nodes" )
            , ( "search remains draft until submitted", (run (Main.Search "needle") loaded).submitted == "" && (run Main.Submit (run (Main.Search "needle") loaded)).submitted == "needle" )
            , ( "Core device search opens World and trims query", searched.perspective == "world" && searched.submitted == "device-name" )
            , ( "empty Core search keeps Core", (run Main.Submit (run (Main.Search "  ") loaded)).perspective == "core" )
            , ( "expanded search result clears search constraints", expanded.perspective == "world" && expanded.focus == "node:1" && expanded.search == "" && expanded.submitted == "" )
            , ( "restoration advances generation and reloads baseline", restored.generation == liveQuery.generation + 1 && restored.status == "Loading" && restored.live )
            , ( "restoration preserves query selection and positions", restored.perspective == liveQuery.perspective && restored.focus == liveQuery.focus && restored.submitted == liveQuery.submitted && restored.search == liveQuery.search && restored.selected == liveQuery.selected && restored.positions == liveQuery.positions )
            , ( "restoration keeps paused mode paused", not (run (incoming 0 "restore" E.null) selected).live )
            , ( "terminal connection failure is actionable", failedConnection.status == "Unavailable" && String.contains "Retry" failedConnection.error )
            , ( "retry restarts terminal live connection", (run Main.Refresh failedConnection).generation == 1 && (run Main.Refresh failedConnection).live && (run Main.Refresh failedConnection).error == "" )
            , ( "edge-only upsert is highlighted and reported in scene", Dict.get changedEdge.id edgeChanged.highlights == Just "changed" && List.any (String.startsWith "Changed relationship:") edgeChanged.recent && not (String.contains "outside" edgeChanged.notice) )
            , ( "new relationship gets added highlight", Dict.get "edge:new" edgeAdded.highlights == Just "added" && List.any (String.startsWith "Added relationship:") edgeAdded.recent )
            , ( "removed relationship clears selection and stays in recent list", edgeRemoved.selected == Nothing && List.any (String.startsWith "Removed relationship:") edgeRemoved.recent && not (String.contains "outside" edgeRemoved.notice) )
            , ( "incident relationship removal is reported", List.any (String.startsWith "Removed relationship:") removed.recent )
            , ( "relationship changes keep recent list bounded", List.length manyEdgeChanges.recent == 12 )
            , ( "pause discards pending transport generation", (run Main.ToggleLive { loaded | live = True }).generation == 1 && not (run Main.ToggleLive { loaded | live = True }).live )
            , ( "null arrays fail decoding", isError (D.decodeString Graph.sceneDecoder (String.replace "\"edges\":[{\"id\":\"edge:index:nodes\",\"source\":\"cell:index\",\"target\":\"cell:nodes\",\"kind\":\"depends on\"}]" "\"edges\":null" sceneJson)) )
            , ( "numeric revisions fail decoding", isError (D.decodeString Graph.sceneDecoder (String.replace "\"90071992547409930\"" "90071992547409930" sceneJson)) )
            , ( "non-string property values fail decoding", isError (D.decodeString Graph.sceneDecoder (String.replace "\"count\":\"2\"" "\"count\":2" sceneJson)) )
            , ( "missing edge endpoint rejected", isError (D.decodeString Graph.sceneDecoder (String.replace "\"target\":\"cell:nodes\"" "\"target\":\"missing\"" sceneJson)) )
            , ( "patch scene bounds enforced", isError (Graph.applyPatch { patch | vertices = List.range 1 201 |> List.map (\n -> { id = String.fromInt n, label = "test", kind = "node", summary = "", changedAt = "", properties = Dict.empty }) } scene) )
            ]

        _ ->
            [ ( "shared scene and patch fixture decoding", False ) ]


isError : Result a b -> Bool
isError result =
    case result of
        Err _ ->
            True

        Ok _ ->
            False
