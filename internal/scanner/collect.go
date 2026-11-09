package scanner

import (
	"context"

	"github.com/levapveeskela/lv24-vigil/internal/rules"
)

// CollectFiles returns the files a scan of opts.Root would inspect. It is used
// by the LLM deep-review pass, which needs file contents rather than findings.
// The same ignore rules, size cap and binary sniff apply.
func (s *Scanner) CollectFiles(ctx context.Context, opts Options) ([]*rules.File, error) {
	root, err := resolveRoot(opts.Root)
	if err != nil {
		return nil, err
	}
	opts.Root = root
	res, err := walkFiles(ctx, root, opts)
	if err != nil {
		return nil, err
	}
	return res.files, nil
}
