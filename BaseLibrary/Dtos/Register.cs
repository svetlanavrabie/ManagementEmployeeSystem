using System.ComponentModel.DataAnnotations;

namespace BaseLibrary.Dtos
{
    public class Register : AccountBase
    {
        [MinLength(5)]
        [MaxLength(100)]
        [Required]
        public string FullName { get; set; }

        [DataType(DataType.Password)]
        [Compare(nameof(Password))]
        [Required]
        public string ConfirmPassword { get; set; }
    }
}
