package cli

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"httpProxy/server"
	"httpProxy/server/auth"
	"os"
)

var (
	serverConfig = appConfig.ServerConfig
	serverCmd    = &cobra.Command{
		Use:   "server",
		Short: "Run EdgeProxy as Forward Server",
		Long:  `Run EdgeProxy as Forward Server`,
		Run: func(cmd *cobra.Command, testSuites []string) {
			var err error

			if Verbose {
				log.SetLevel(log.DebugLevel)
				log.Debug("Verbose mode enabled")
			}

			if err = serverConfig.Validate(); err != nil {
				log.Errorf("invalid Server Parameters %v", err)
				os.Exit(invalidConfig)
			}

			auth.SetValidationKey(serverConfig.PublicKeyPath)
			webSocketRelay := server.NewHttpServer(cmd.Context(), serverConfig.HttpPort, serverConfig.PublicKeyPath)
			webSocketRelay.Start()

			<-cmd.Context().Done()
			webSocketRelay.Stop()
			os.Exit(exitCode)
		},
	}
)

func init() {
	RootCmd.AddCommand(serverCmd)
	serverCmd.PersistentFlags().IntVar(&serverConfig.HttpPort, "http-port", serverConfig.HttpPort, "Http WebSocket Server Listen Port")
	serverCmd.PersistentFlags().StringVar(&serverConfig.PublicKeyPath, "public-key", serverConfig.PublicKeyPath, "Path to a public pem")
}
