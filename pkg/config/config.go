package config

type ConfigModel struct {
	EsUrl string `json:"es_url"`
}

var Config = ConfigModel{
	EsUrl: "http://127.0.0.1:9200",
}
