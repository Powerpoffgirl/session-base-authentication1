function forgotPassword() {
  window.location.href = "/forgotPasswordPage";
}
function resendVerificationMail() {
  window.location.href = "/resendVerificationMail";
}

let skip = 0;

document.addEventListener("click", function (event) {
  if (event.target.classList.contains("add_item")) {
    // event.preventDefault();
    console.log("add item");
    const bookTitle = document.getElementById("bookTitle");
    const bookAuthor = document.getElementById("bookAuthor");
    const bookPrice = document.getElementById("bookPrice");
    const bookCategory = document.getElementById("bookCategory");
    console.log(bookTitle.value);
    console.log(bookAuthor.value);
    console.log(bookPrice.value);
    console.log(bookCategory.value);
    if (bookTitle.value === "") {
      alert("Please enter book title");
      return;
    }
    axios
      .post("/create-item", {
        book: {
          bookTitle: bookTitle.value,
          bookAuthor: bookAuthor.value,
          bookPrice: bookPrice.value,
          bookCategory: bookCategory.value,
        },
      })
      .then((res) => {
        console.log(res);
        if (res.data.status !== 201) {
          alert(res.data.message);
        }
        bookTitle.value = "";
        bookAuthor.value = "";
        bookPrice.value = "";
        bookCategory.value = "";
      })
      .catch((err) => {
        console.log(err);
        alert(err);
      });
    return;
  }
  if (event.target.classList.contains("edit-me")) {
    const id = event.target.getAttribute("data-id");
    const newBookTitle = prompt("Enter your new book title");
    const newBookAuthor = prompt("Enter your new book author");
    const newBookPrice = prompt("Enter your new book price");
    const newBookCategory = prompt("Enter your new book Category");
    const bookTitle = document.getElementById("bookTitle");
    const bookAuthor = document.getElementById("bookAuthor");
    const bookPrice = document.getElementById("bookPrice");
    const bookCategory = document.getElementById("bookCategory");
    console.log(id, newBookTitle, newBookAuthor, newBookPrice, newBookCategory);
    axios
      .post("/edit-item", {
        id,
        newBookTitle,
        newBookAuthor,
        newBookPrice,
        newBookCategory,
      })
      .then((res) => {
        if (res.data.status !== 200) {
          alert(res.data.message);
          return;
        }
        bookTitle.innerText = newBookTitle;
        bookAuthor.innerText = newBookAuthor;
        bookPrice.innerText = newBookPrice;
        bookCategory.innerText = newBookCategory;
      })
      .catch((err) => {
        console.log(err);
        alert(err);
      });
  }

  if (event.target.classList.contains("delete-me")) {
    const id = event.target.getAttribute("data-id");
    axios
      .post("/delete-item", { id })
      .then((res) => {
        if (res.data.status !== 200) {
          alert(res.data.message);
          return;
        }
        event.target.parentElement.parentElement.remove();
        return;
      })
      .catch((err) => {
        console.log(err);
        alert(err);
      });
  }
  if (event.target.classList.contains("show_more")) {
    generateBooks();
  }
});

window.onload = function () {
  generateBooks();
};

function generateBooks() {
  //read the todos
  console.log(skip);
  axios
    .get(`/pagination_dashboard?skip=${skip}`)
    .then((res) => {
      if (res.data.status !== 200) {
        alert(res.data.message);
        return;
      }
      console.log(res.data);
      const books = res.data.data;
      console.log(books);
      document.getElementById("item_list").insertAdjacentHTML(
        "beforeend",
        books
          .map((book) => {
            return `
            <div class="col-md-4 mb-4">
            <div class="card">
              <div class="card-body">
                <h5 class="card-title">${book.bookTitle}</h5>
                <p class="card-text"> ${book.bookAuthor}</p>
                <h5 class="card-text">${book.bookPrice}</h5>
                <span class="book-category"> ${book.bookCategory}</span>
                <button data-id="${book._id}" class="edit-me btn btn-primary btn-sm mr-1">Update</button>
                <button data-id="${book._id}" class="delete-me btn btn-danger btn-sm">Delete</button>
                </div>
              </div>
              </div>
           `;
          })
          .join("")
      );
      // increment skip by books length
      skip += books.length;
    })
    .catch((err) => {
      console.log(err);
    });
}

//CRUD
