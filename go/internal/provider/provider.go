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
