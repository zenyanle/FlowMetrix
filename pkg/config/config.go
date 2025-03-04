package config

import (
	"log"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// Config 是全局配置对象
var Config *viper.Viper
var once sync.Once

// LoadConfig 负责加载多个配置文件
func LoadConfig(env string) {
	once.Do(func() {
		Config = viper.New()

		// 允许使用环境变量覆盖
		Config.AutomaticEnv()
		Config.SetEnvKeyReplacer(strings.NewReplacer(".", "_")) // 允许 `APP_PORT` 代替 `app.port`

		// 加载通用配置
		// loadFile("config/config")

		// 按环境加载，如 config.dev.yaml
		// if env != "" {
		// 	loadFile(fmt.Sprintf("config/config.%s", env))
		//}

		// 加载其他子配置
		if env == "" {
			loadFile("configs/server/config.yaml")
			loadFile("configs/server/file_rules.yaml")
			loadFile("configs/client/config.yaml")
			loadFile("configs/client/grpc_servers.yaml")
			loadFile("configs/server/instructions.yaml")
		}

		if env == "server" {
			loadFile("configs/server/config.yaml")
			loadFile("configs/server/file_rules.yaml")
			loadFile("configs/server/instructions.yaml")
		}

		if env == "client" {
			loadFile("configs/client/config.yaml")
			loadFile("configs/client/grpc_servers.yaml")
		}

		//loadFile("config/client")

		// 监听配置文件修改
		Config.WatchConfig()
		Config.OnConfigChange(func(e fsnotify.Event) {
			log.Println("⚡ 配置文件变更:", e.Name)
		})

		log.Println("✅ 配置加载完成")
	})
}

// loadFile 加载 YAML 配置文件
func loadFile(filePath string) {
	v := viper.New()
	v.SetConfigName(filePath)
	v.SetConfigType("yaml")
	v.AddConfigPath(".") // 配置文件路径

	if err := v.ReadInConfig(); err == nil {
		Config.MergeConfigMap(v.AllSettings()) // 合并配置
		log.Println("📄 加载配置:", v.ConfigFileUsed())
	} else {
		log.Printf("⚠️ 配置文件 [%s] 未找到，跳过: %v\n", filePath, err)
	}
}

// Get 获取配置项
func Get(key string) interface{} {
	return Config.Get(key)
}
