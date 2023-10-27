package vercel_blob

import (
	"fmt"
	"strings"
	"testing"
)

func Test_CountFiles(t *testing.T) {
	client := NewVercelBlobClient()
	allFiles, err := client.List(ListCommandOptions{})
	if err != nil {
		t.Error(err)
		return
	} else {
		fmt.Println(len(allFiles.Blobs))
	}
}

func Test_PutWithRandomSuffix(t *testing.T) {
	client := NewVercelBlobClient()
	file1, err := client.Put(
		"vercel_blob_unittest/a.txt",
		strings.NewReader("test body"),
		PutCommandOptions{
			AddRandomSuffix: true,
			ContentType:     "text/plain",
		})
	if err != nil {
		t.Error(err)
		return
	} else {
		fmt.Println(file1.URL)
	}
}

func Test_Partial_Download(t *testing.T) {
	client := NewVercelBlobClient()
	bytes, err := client.Download("vercel_blob_unittest/a.txt",
		DownloadCommandOptions{
			ByteRange: &Range{0, 4},
		})
	if err != nil {
		t.Error(err)
		return
	} else {
		fmt.Println(string(bytes))
	}
}
