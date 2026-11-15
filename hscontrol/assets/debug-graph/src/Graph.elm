module Graph exposing (Edge, Patch, Scene, Vertex, applyPatch, edgeDecoder, edgeLimit, patchDecoder, sceneDecoder, selection, vertexDecoder, vertexLimit)

import Dict exposing (Dict)
import Json.Decode as D exposing (Decoder)
import Json.Encode as E
import Set



-- The scene bounds of hscontrol/state/debug_graph.go; a larger scene is refused.


vertexLimit : Int
vertexLimit =
    200


edgeLimit : Int
edgeLimit =
    1000


type alias Vertex =
    { id : String, label : String, kind : String, summary : String, changedAt : String, properties : Dict String String }


type alias Edge =
    { id : String, source : String, target : String, kind : String }


type alias Scene =
    { revision : String, timestamp : String, perspective : String, search : String, focus : String, vertices : List Vertex, edges : List Edge, totalNodes : Int, matchedNodes : Int, shownNodes : Int, limit : Int, truncated : Bool, policyError : String }


type alias Patch =
    { baseRevision : String, revision : String, timestamp : String, vertices : List Vertex, edges : List Edge, removedVertices : List String, removedEdges : List String, totalNodes : Int, matchedNodes : Int, shownNodes : Int, limit : Int, truncated : Bool, policyError : String }


field : String -> Decoder a -> Decoder (a -> b) -> Decoder b
field name decoder =
    D.map2 (|>) (D.field name decoder)


vertexDecoder : Decoder Vertex
vertexDecoder =
    D.map6 Vertex (D.field "id" D.string) (D.field "label" D.string) (D.field "kind" D.string) (D.field "summary" D.string) (D.field "changedAt" D.string) (D.field "properties" (D.dict D.string))


edgeDecoder : Decoder Edge
edgeDecoder =
    D.map4 Edge (D.field "id" D.string) (D.field "source" D.string) (D.field "target" D.string) (D.field "kind" D.string)


sceneDecoder : Decoder Scene
sceneDecoder =
    D.succeed Scene
        |> field "revision" D.string
        |> field "timestamp" D.string
        |> field "perspective" D.string
        |> field "search" D.string
        |> field "focus" D.string
        |> field "vertices" (D.list vertexDecoder)
        |> field "edges" (D.list edgeDecoder)
        |> field "totalNodes" D.int
        |> field "matchedNodes" D.int
        |> field "shownNodes" D.int
        |> field "limit" D.int
        |> field "truncated" D.bool
        |> field "policyError" D.string
        |> D.andThen validateScene


validateScene : Scene -> Decoder Scene
validateScene scene =
    let
        ids =
            Set.fromList (List.map .id scene.vertices)

        edgeIds =
            Set.fromList (List.map .id scene.edges)
    in
    if List.length scene.vertices > vertexLimit || List.length scene.edges > edgeLimit then
        D.fail ("Scene exceeds the " ++ String.fromInt vertexLimit ++ " object / " ++ String.fromInt edgeLimit ++ " relationship limit. Narrow the search.")

    else if Set.size ids /= List.length scene.vertices || Set.size edgeIds /= List.length scene.edges || List.any (\e -> not (Set.member e.source ids && Set.member e.target ids)) scene.edges then
        D.fail "Scene contains duplicate IDs or missing relationship endpoints."

    else
        D.succeed scene


patchDecoder : Decoder Patch
patchDecoder =
    D.succeed Patch
        |> field "baseRevision" D.string
        |> field "revision" D.string
        |> field "timestamp" D.string
        |> field "vertices" (D.list vertexDecoder)
        |> field "edges" (D.list edgeDecoder)
        |> field "removedVertices" (D.list D.string)
        |> field "removedEdges" (D.list D.string)
        |> field "totalNodes" D.int
        |> field "matchedNodes" D.int
        |> field "shownNodes" D.int
        |> field "limit" D.int
        |> field "truncated" D.bool
        |> field "policyError" D.string


applyPatch : Patch -> Scene -> Result String Scene
applyPatch patch scene =
    if patch.baseRevision /= scene.revision then
        Err "Revision changed; requesting a fresh baseline."

    else
        let
            vertices =
                merge patch.removedVertices patch.vertices scene.vertices

            ids =
                Set.fromList (List.map .id vertices)

            edges =
                merge patch.removedEdges patch.edges scene.edges
                    |> List.filter (\e -> Set.member e.source ids && Set.member e.target ids)

            next =
                { scene | revision = patch.revision, timestamp = patch.timestamp, vertices = vertices, edges = edges, totalNodes = patch.totalNodes, matchedNodes = patch.matchedNodes, shownNodes = patch.shownNodes, limit = patch.limit, truncated = patch.truncated, policyError = patch.policyError }
        in
        D.decodeValue (validateScene next) E.null
            |> Result.mapError D.errorToString


merge : List String -> List { a | id : String } -> List { a | id : String } -> List { a | id : String }
merge removed updates old =
    let
        deleted =
            Set.fromList removed
    in
    List.filter (\v -> not (Set.member v.id deleted)) old
        |> List.map (\v -> ( v.id, v ))
        |> Dict.fromList
        |> (\items -> List.foldl (\v -> Dict.insert v.id v) items updates)
        |> Dict.values


selection : Scene -> Maybe String -> Maybe String
selection scene selected =
    selected
        |> Maybe.andThen
            (\id ->
                if List.any (\v -> v.id == id) scene.vertices || List.any (\e -> e.id == id) scene.edges then
                    Just id

                else
                    Nothing
            )
