package converge

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

var (
	// ErrDuplicateNode reports two nodes registered with the same ID.
	ErrDuplicateNode = errors.New("converge: duplicate node id")
	// ErrUnknownDependency reports a node dependency referencing an unregistered node ID.
	ErrUnknownDependency = errors.New("converge: unknown dependency")
	// ErrCycleDetected reports a cycle in the node dependency graph.
	ErrCycleDetected = errors.New("converge: cycle detected")
	// ErrUnknownTarget reports an unrecognized node ID or stage selector passed to Subgraph.
	ErrUnknownTarget = errors.New("converge: unknown target")
)

// Graph holds a validated, topologically ordered set of reconciliation nodes.
type Graph struct {
	byID    map[string]Node
	deps    map[string][]string
	ordered []Node
}

// NewGraph validates node uniqueness, dependency existence, and acyclicity and builds a deterministic Graph.
func NewGraph(nodes ...Node) (*Graph, error) {
	byID, err := indexNodes(nodes)
	if err != nil {
		return nil, err
	}
	deps, dependents, inDegree, err := buildDependencyMaps(nodes, byID)
	if err != nil {
		return nil, err
	}
	ordered, err := sortTopologically(nodes, byID, dependents, inDegree)
	if err != nil {
		return nil, err
	}
	return &Graph{
		byID:    byID,
		deps:    deps,
		ordered: ordered,
	}, nil
}

// Order returns all nodes in deterministic topological order.
func (g *Graph) Order() []Node {
	return slices.Clone(g.ordered)
}

// Subgraph returns the ordered subset of nodes required to reach target (a node ID, stage selector, or empty for all).
func (g *Graph) Subgraph(target string) ([]Node, error) {
	if target == "" {
		return g.Order(), nil
	}
	seeds, err := g.resolveTargetSeeds(target)
	if err != nil {
		return nil, err
	}
	included := g.collectAncestors(seeds)
	result := make([]Node, 0, len(included))
	for _, n := range g.ordered {
		if _, ok := included[n.ID()]; ok {
			result = append(result, n)
		}
	}
	return result, nil
}

func indexNodes(nodes []Node) (map[string]Node, error) {
	byID := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		id := n.ID()
		if _, exists := byID[id]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateNode, id)
		}
		byID[id] = n
	}
	return byID, nil
}

func buildDependencyMaps(nodes []Node, byID map[string]Node) (map[string][]string, map[string][]string, map[string]int, error) {
	deps := make(map[string][]string, len(nodes))
	dependents := make(map[string][]string, len(nodes))
	inDegree := make(map[string]int, len(nodes))

	for _, n := range nodes {
		id := n.ID()
		deduped, err := validateNodeDeps(id, n.DependsOn(), byID)
		if err != nil {
			return nil, nil, nil, err
		}
		deps[id] = deduped
		inDegree[id] = len(deduped)
		for _, dep := range deduped {
			dependents[dep] = append(dependents[dep], id)
		}
	}
	return deps, dependents, inDegree, nil
}

func validateNodeDeps(id string, rawDeps []string, byID map[string]Node) ([]string, error) {
	seen := make(map[string]struct{}, len(rawDeps))
	deduped := make([]string, 0, len(rawDeps))
	for _, dep := range rawDeps {
		if dep == id {
			return nil, fmt.Errorf("%w: %s depends on itself", ErrCycleDetected, id)
		}
		if _, exists := byID[dep]; !exists {
			return nil, fmt.Errorf("%w: %s depends on %s", ErrUnknownDependency, id, dep)
		}
		if _, duplicate := seen[dep]; duplicate {
			continue
		}
		seen[dep] = struct{}{}
		deduped = append(deduped, dep)
	}
	return deduped, nil
}

func sortTopologically(nodes []Node, byID map[string]Node, dependents map[string][]string, inDegree map[string]int) ([]Node, error) {
	ready := make([]Node, 0, len(nodes))
	for _, n := range nodes {
		if inDegree[n.ID()] == 0 {
			ready = append(ready, n)
		}
	}
	slices.SortFunc(ready, compareNodeOrder)

	ordered := make([]Node, 0, len(nodes))
	for len(ready) > 0 {
		cur := ready[0]
		ready = ready[1:]
		ordered = append(ordered, cur)

		for _, childID := range dependents[cur.ID()] {
			inDegree[childID]--
			if inDegree[childID] == 0 {
				ready = append(ready, byID[childID])
			}
		}
		slices.SortFunc(ready, compareNodeOrder)
	}

	if len(ordered) < len(nodes) {
		remaining := collectCyclicIDs(nodes, inDegree)
		return nil, fmt.Errorf("%w: %s", ErrCycleDetected, strings.Join(remaining, ", "))
	}
	return ordered, nil
}

func collectCyclicIDs(nodes []Node, inDegree map[string]int) []string {
	var remaining []string
	for _, n := range nodes {
		if inDegree[n.ID()] > 0 {
			remaining = append(remaining, n.ID())
		}
	}
	slices.Sort(remaining)
	return remaining
}

func compareNodeOrder(a, b Node) int {
	if c := cmp.Compare(a.Stage(), b.Stage()); c != 0 {
		return c
	}
	return cmp.Compare(a.ID(), b.ID())
}

func (g *Graph) resolveTargetSeeds(target string) ([]string, error) {
	if _, ok := g.byID[target]; ok {
		return []string{target}, nil
	}
	stage, ok := parseStageTarget(target)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownTarget, target)
	}
	var seeds []string
	for _, n := range g.ordered {
		if n.Stage() <= stage {
			seeds = append(seeds, n.ID())
		}
	}
	return seeds, nil
}

func parseStageTarget(target string) (Stage, bool) {
	trimmed := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(target)), "stage-")
	val, err := strconv.Atoi(trimmed)
	if err != nil || val < int(StageHostPrereqs) || val > int(StageDownstream) {
		return 0, false
	}
	return Stage(val), true
}

func (g *Graph) collectAncestors(seeds []string) map[string]struct{} {
	included := make(map[string]struct{}, len(seeds))
	stack := slices.Clone(seeds)
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, seen := included[id]; seen {
			continue
		}
		included[id] = struct{}{}
		stack = append(stack, g.deps[id]...)
	}
	return included
}
