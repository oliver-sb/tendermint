package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/spf13/cobra"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/types"

	"github.com/valyala/fasthttp"
)

func NewOverCmd(logger log.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "over",
		Short: "over",
		Long:  fmt.Sprintf(`Generate Bash and Zsh completion scripts and print them to STDOUT.`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			run(logger)

			return nil
		},
	}

	return cmd
}

func run(logger log.Logger) {
	logger.Info("Run Over")

	url := "https://lcd.terra.dev/blocks/latest"

	req := fasthttp.AcquireRequest()
	req.SetRequestURI(url)
	req.Header.SetMethod("GET")

	resp := fasthttp.AcquireResponse()
	client := &fasthttp.Client{}
	defer client.CloseIdleConnections()
	defer resp.ConnectionClose()

	err := client.DoTimeout(req, resp, 10*time.Second)
	if err != nil {
		logger.Error("Error on RequestRPC : %+v\n", err)
		return
	}
	if resp.StatusCode() != fasthttp.StatusOK {
		logger.Error("StatusCode not OK : %s\n", resp.String())
		return
	}

	var resultBlock struct {
		BlockID types.BlockID `json:"block_id"`
		Block   struct {
			types.Header `json:"header"`
			LastCommit   *types.Commit `json:"last_commit"`
		} `json:"block"`
	}
	err = json.Unmarshal(resp.Body(), &resultBlock)
	if err != nil {
		logger.Error("", "error", err)
		return
	}

	block := resultBlock.Block

	signedHeader := types.SignedHeader{
		Header: &block.Header,
		Commit: block.LastCommit,
	}

	//logger.Info("", "last commit: ", block.LastCommit, "signed header", signedHeader)

	protoHeader := signedHeader.ToProto()

	byteData, err := proto.Marshal(protoHeader)
	if err != nil {
		logger.Error("", "error", err)
		return
	}

	encoded := base64.RawStdEncoding.EncodeToString(byteData)
	logger.Info("", "encoded", len(encoded), "byte data", len(byteData))

	//logger.Info("", "data", resultBlock["block"].(map[string]interface{})["header"])
	//logger.Info("", "data", resultBlock["block"].(map[string]interface{})["last_commit"])
}
