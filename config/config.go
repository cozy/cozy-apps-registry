package config

import (
	"fmt"

	"github.com/cozy/swift"
	"github.com/spf13/viper"
)

type Config struct {
	SwiftConnection *swift.Connection
}

func NewConfig() (*Config, error) {
	sc, err := initSwiftConnection()
	if err != nil {
		return nil, err
	}
	return &Config{
		SwiftConnection: sc,
	}, nil
}

func initSwiftConnection() (*swift.Connection, error) {
	endpointType := viper.GetString("swift.endpoint_type")

	// Create the swift connection
	swiftConnection := swift.Connection{
		UserName:     viper.GetString("swift.username"),
		ApiKey:       viper.GetString("swift.api_key"), // Password
		AuthUrl:      viper.GetString("swift.auth_url"),
		EndpointType: swift.EndpointType(endpointType),
		Tenant:       viper.GetString("swift.tenant"), // Projet name

		Domain: viper.GetString("swift.domain"),
	}
	// Authenticate
	err := swiftConnection.Authenticate()
	if err != nil {
		panic(err)
	}

	// Prepare containers
	spacesNames := viper.GetStringSlice("spaces")
	for _, space := range spacesNames {
		if _, _, err := swiftConnection.Container(space); err != nil {
			fmt.Printf("Creating container for space %s\n", space)
			err = swiftConnection.ContainerCreate(space, nil)
			if err != nil {
				return nil, err
			}
		}
	}
	return &swiftConnection, nil
}
