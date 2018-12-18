package nbgin

import (
	"reflect"
	"strings"
	"sync"

	"git.cm/naiba/ucenter"

	"github.com/gin-gonic/gin/binding"
	validator "gopkg.in/go-playground/validator.v9"
	cn_translations "gopkg.in/go-playground/validator.v9/translations/zh"
)

type DefaultValidator struct {
	once     sync.Once
	validate *validator.Validate
}

var _ binding.StructValidator = &DefaultValidator{}

func (v *DefaultValidator) ValidateStruct(obj interface{}) error {
	if kindOfData(obj) == reflect.Struct {
		v.lazyinit()
		if err := v.validate.Struct(obj); err != nil {
			return error(err)
		}
	}
	return nil
}

func (v *DefaultValidator) Engine() interface{} {
	v.lazyinit()
	return v.validate
}

func (v *DefaultValidator) lazyinit() {
	v.once.Do(func() {
		v.validate = validator.New()
		cn_translations.RegisterDefaultTranslations(v.validate, ucenter.ValidatorTrans)
		v.validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
			// Custom field name 自定义字段名称
			name := strings.SplitN(fld.Tag.Get("cfn"), ",", 2)[0]
			if name == "-" {
				return ""
			}
			return name
		})
		v.validate.SetTagName("binding")

		// add any custom validations etc. here
	})
}

func kindOfData(data interface{}) reflect.Kind {

	value := reflect.ValueOf(data)
	valueType := value.Kind()

	if valueType == reflect.Ptr {
		valueType = value.Elem().Kind()
	}
	return valueType
}
