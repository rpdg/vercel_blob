package vercel_blob

import (
	"fmt"
	"io"
	"os"
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
	f, _ := os.Open("a.png")
	defer f.Close()
	file1, err := client.Put(
		"vercel_blob_unittest/a.png",
		io.Reader(f),
		PutCommandOptions{
			AddRandomSuffix: true,
			//ContentType:     "multipart/form-data",
		})
	if err != nil {
		t.Error(err)
		return
	} else {
		fmt.Println(file1.URL)
	}
}

func Test_Copy(t *testing.T) {
	//https://fetegzn4vw3t5yqf.public.blob.vercel-storage.com/vercel_blob_unittest/a.txt
	client := NewVercelBlobClient()
	res, err := client.Copy("https://fetegzn4vw3t5yqf.public.blob.vercel-storage.com/vercel_blob_unittest/a.txt",
		"vercel_blob_unittest/B.txt",
		PutCommandOptions{})
	if err != nil {
		t.Error(err)
		return
	} else {
		fmt.Println(res.URL)
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
