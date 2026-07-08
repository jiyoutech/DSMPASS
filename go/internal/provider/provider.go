package provider

type User struct {
	ProviderSlug       string
	Subject            string
	SubjectType        string
	DisplayName        string
	Email              string
	Mobile             string
	DepartmentSubjects []string
	Active             bool
}

type Group struct {
	ProviderSlug  string
	Subject       string
	ParentSubject string
	Name          string
	Path          string
}

type Directory interface {
	Slug() string
	ListUsers() ([]User, error)
	ListGroups() ([]Group, error)
	ListGroupMembers(groupSubject string) ([]string, error)
}

type SnapshotDirectory interface {
	Directory
	ListUsersAndGroups() ([]User, []Group, error)
}

type OAuth interface {
	Slug() string
	BuildAuthorizeURL(state, redirectURI string) string
	ExchangeCode(code, redirectURI string) (map[string]any, error)
	FetchProfile(token map[string]any) (map[string]any, error)
	ProfileSubject(profile map[string]any) (string, string)
}

type Named interface {
	ProviderDisplayName() string
}
